import { expect } from 'chai'
import { History } from 'history'
import 'mocha'
import * as td from 'testdouble'

import { Auth0Lock } from './auth0-lock'
import { PathMatch } from '../auth-flow'
import { Auth0Config } from '../auth0'


describe('Auth0Lock', () => {
    const allowedPaths: PathMatch[] = [
        {path: '/', mode: 'full'},
        {path: '/admin/', mode: 'prefix'}
    ];

    const auth0Config: Auth0Config = {
        clientId: 'some-id',
        clientSecret: 'someSecret',
        domain: 'the-domain',
        loginCallbackUri: '/auth/login'
    };

    it('can be constructed', () => {
        const history = td.object({});

        const auth0Lock = new Auth0Lock(history as History, allowedPaths, auth0Config);

        expect(auth0Lock).is.not.null;
    });
});
