import base64url from 'base64url';
import { Issuer } from 'openid-client';
import { api, common } from '@nfjs/core';
import { dbapi } from '@nfjs/back';

function now() {
    return Math.floor(Date.now() / 1000);
}

export class ClientOpenId {
    constructor({ config, container }) {
        this.config = config;
        this.container = container;
    }

    /**
     * Инициализация инстанса
     * @return {Promise<void>}
     */
    async init() {
        try {
            const issuer = await Issuer.discover(this.config.openid_config);
            const clientOptions = {
                response_types: ['code'],
                ...this.config?.client
            };
            this.client = new issuer.Client(clientOptions);
        } catch (e) {
            this.container.logger.log('error', e, { method: 'init' });
        }
    }

    /**
     * Получение url для авторизации
     * @returns {Promise<{data: {url: string}}>}
     */
    getAuthUrl() {
        const options = {};
        if (this.config?.scope) options.scope = this.config.scope.join(' ');
        return this.client.authorizationUrl(options);
    }

    /**
     * Получение url для выхода пользователя
     * @param {Object} tokenSet - сессия пользователя на веб сервере
     * @param {string} [post_logout_redirect_url] - кастомизированный url для перехода после процесса выхода в авторизующем центре
     * @returns {Promise<string>}
     */
    async getLogoutUrl(tokenSet, post_logout_redirect_url) {
        // когда не нужно заканчивать сессию в авторизующем центре
        if (!(this.config?.logoutInIssuer ?? true)) return '/';
        // когда нужно формируется endSessionUrl с адресом на который нужно будет перенаправить обратно в приложение
        let _tokenSet = tokenSet;
        try {
            if (_tokenSet && _tokenSet.refresh_token && (_tokenSet.expires_at - now() < 0)) {
                _tokenSet = await this.client.refresh(_tokenSet.refresh_token);
            }
        } catch (e) {
            this.container.logger.log('error', e, { method: 'getLogoutUrl' });
        }

        let url = '/';
        try {
            url = this.client.endSessionUrl({
                id_token_hint: _tokenSet.id_token,
                post_logout_redirect_uri: post_logout_redirect_url || this.config.client.post_logout_redirect_uris?.[0] || this.config.client.redirect_uris?.[0],
                state: 'logout'
            });
        } catch(e) {
            this.container.logger.log('error', e, { method: 'getLogoutUrl' });
        }
        return url;
    }

    /**
     * Получить обновленные токены по refresh токену
     * @param {Object} tokenSet
     * @return {Promise<Object>}
     */
    async refresh(tokenSet) {
        let newTokenSet;
        try {
            if (tokenSet.refresh_token)
                newTokenSet = await this.client.refresh(tokenSet.refresh_token);
        } catch(e) {
            this.container.logger.log('error', e, { method: 'refresh' });
        }
        return newTokenSet;
    }

    /**
     * Обработка обратного вызова центром авторизации
     * @param {RequestContext} context - контекст выполнения запроса
     * @returns {Promise<void>}
     */
    async callback(context) {
        let connectDb;
        try {
            const params = this.client.callbackParams(context.req);
            if (params.state === 'logout') {
                context.headers({Location: '/'}).code(302).end();
                return;
            }

            const tokenSet = await this.client.callback(this.config.client.redirect_uris[0], params);
            let accessInfo, userInfo;
            try {
                accessInfo = JSON.parse(base64url.decode(tokenSet.access_token.split('.')[1]));
            } catch(e) {
                accessInfo = {};
            }
            // сбор информации о пользователе
            userInfo = tokenSet.claims();
            userInfo._org = this.config?.org;
            userInfo._roles_scope = this.config?.roles_scope;
            const roles = new Set(this.config?.roles_default ?? []);
            const incRoles = common.getPath((this.config?.roles_place ?? 'id') === 'id' ? userInfo : accessInfo, this.config?.roles_path ?? 'roles');
            if (incRoles) {
                incRoles.forEach(role => roles.add(role));
            }
            userInfo._roles = [...roles];
            userInfo._username = common.getPath(userInfo, this.config?.username_path ?? 'preferred_username');
            userInfo._fullname = common.getPath(userInfo, this.config?.fullname_path ?? 'name');
            context.session.set('openid-token', tokenSet);
            context.session.set('openid-userinfo', userInfo);

            // вызов всех хуков на "до процесса авторизации в системе"
            await api.processHooks('authOpenIdBefore', this, context);
            // Если требуется соединение с бд из дефолтного провайдера. Например, для сохранения обновленной информации о пользователе
            if (!!this.config?.useConnectToDb) {
                connectDb = await dbapi.getConnect(context);
            }
            // вызов всех хуков на "процесс авторизации в системе"
            await api.processHooks('authOpenId', this, context, connectDb);
            // перекладывание информации из токена(id_token) в сессию пользователя в область для клиента
            if (this.config.client_scope) {
                context.session.assign('context.client', this.config.client_scope.reduce((clCntx, n) => {
                    clCntx[n] = common.getPath(userInfo, n);
                    return clCntx;
                }, {}));
            }
            // выставить контекст для сессии в бд в текущий коннект для дальнейшей работы уже под пользователем
            // при успешном выполнении считаем, что уже пользователь авторизован
            if (connectDb) {
                const dbPreparedContext = context.session.prepareProviderContext(connectDb._provider);
                await connectDb.context(dbPreparedContext);
            }
            context.session.set('authProvider','openid');
            // выполнение хуков на "после авторизации в системе под пользователем"
            // пользователь уже считается полностью прошедшим авторизации и все хуки выполняются уже под его учетной записью
            await api.processHooks('authOpenIdAfter', this, context, connectDb);
            context.headers({Location: '/'}).code(302).end();
        } catch (e) {
            this.container.logger.log('error', e, { state: 'callback' });
            await this.logout(context, this.config.post_error_redirect_url);
        } finally {
            if (connectDb) connectDb.release();
        }
    }

    /**
     * Процесс выхода пользователя из системы
     * @param {RequestContext} context - контекст выполнения запроса
     * @param {string} [post_logout_redirect_url] - кастомизированный url для перехода после процесса выхода в авторизующем центре
     * @returns {Promise<void>}
     */
    async logout(context, post_logout_redirect_url) {
        try {
            const tokenSet = context.session.get('openid-token');
            const url = await this.getLogoutUrl(tokenSet, post_logout_redirect_url);
            context.session.destroy();
            context.headers({Location: url}).code(302).end();
        } catch(e) {
            this.container.logger.log('error', e, { method: 'logout' });
        }
    }
}
