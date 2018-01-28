import { expect } from 'chai'
import 'mocha'

import { Auth0Lock } from './auth0-lock'
import { PathMatch } from '../auth-flow'
import { Auth0ClientConfig } from '../auth0'


describe('Auth0Lock', () => {
    const allowedPaths: PathMatch[] = [
        {path: '/', mode: 'full'},
        {path: '/admin/', mode: 'prefix'}
    ];

    const auth0ClientConfig: Auth0ClientConfig = {
        clientId: 'some-id',
        domain: 'the-domain',
        loginCallbackUri: '/auth/login'
    };

    it('can be constructed', () => {
        const auth0Lock = new Auth0Lock(allowedPaths, auth0ClientConfig);

        expect(auth0Lock).is.not.null;
    });
});
















