import { config, container } from '@nfjs/core';
import { web } from '@nfjs/back';
import { authProviders } from '@nfjs/auth';
import { ClientOpenId } from './src/client.js';
import { AuthProviderOpenId } from './src/auth-provider.js';

async function init() {
    const configOpenId = config?.['@nfjs/auth-openid'];
    const clientOpenId = new ClientOpenId({ config: configOpenId, container });
    await clientOpenId.init();
    authProviders.openid = new AuthProviderOpenId({ client: clientOpenId });
    web.on('GET', '/openid/callback', { middleware: ['session'] }, ctx => clientOpenId.callback(ctx) );
    // переопределение роута проверки залогиненности пользователя в приложении
    web.on('POST', '/front/action/checkSession', { override: true, middleware: ['session'] }, (context) => {
        // возвращается адрес, на который нужно перенаправить пользователя для аутентификации
        // и признак авторизованности (true - авторизован, false - требуется перенаправление)
        let data = {
            redirect_url: clientOpenId.getAuthUrl(),
            result: !!context.session.get('authProvider')
        };
        context.send({ data }, true);
    });
}

const meta = {
    require: {
        after: [
            "@nfjs/front-pl",
            "@nfjs/winston-logger"
        ]
    }
}

export {
    meta,
    init,
};
