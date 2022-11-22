function now() {
    return Math.floor(Date.now() / 1000);
}

export class AuthProviderOpenId {
    constructor({ client }) {
        this.client = client;
    }

    login(user, password, session) {

    }

    async logout(session) {
        const tokenSet = session.get('openid-token');
        const url = await this.client.getLogoutUrl(tokenSet);
        session.destroy();
        return { status: 'redirect', redirect_url: url };
    }

    async validate(session) {
        let tokenSet = session.get('openid-token');
        if (tokenSet.expires_at - now() < 0) {
            const newTokenSet = await this.client.refresh(tokenSet);
            if (newTokenSet) {
                session.set('openid-token', tokenSet);
                return true;
            } else {
                return false
            }
        } else {
            return true;
        }
    }
}