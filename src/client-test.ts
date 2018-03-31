import { expect } from 'chai'
import * as HttpStatus from 'http-status-codes'
import 'mocha'
import { MarshalFrom } from 'raynor'
import * as td from 'testdouble'
import * as uuid from 'uuid'

import { Env, WebFetcher } from '@truesparrow/common-js'

import {
    IdentityClient,
    IdentityError,
    newIdentityClient,
    SESSION_TOKEN_HEADER_NAME,
    UnauthorizedIdentityError,
    XSRF_TOKEN_HEADER_NAME
} from './client'
import { SessionAndTokenResponse, SessionResponse, UsersInfoResponse } from './dtos'
import {
    PrivateUser,
    PublicUser,
    Role,
    Session,
    SessionState,
    UserState
} from './entities'
import { SessionToken } from './session-token'


describe('IdentityError', () => {
    it('should construct a proper error', () => {
        const error = new IdentityError('A problem');
        expect(error.name).to.eql('IdentityError');
        expect(error.message).to.eql('A problem');
        expect(error.stack).to.be.not.null;
    });
});


describe('UnauthorizedIdentityError', () => {
    it('should construct a proper error', () => {
        const error = new UnauthorizedIdentityError('A problem');
        expect(error.name).to.eql('UnauthorizedIdentityError');
        expect(error.message).to.eql('A problem');
        expect(error.stack).to.be.not.null;
    });
});


describe('IdentityClient', () => {
    const sessionTokenMarshaller = new (MarshalFrom(SessionToken))();
    const sessionAndTokenResponseMarshaller = new (MarshalFrom(SessionAndTokenResponse))();
    const sessionResponseMarshaller = new (MarshalFrom(SessionResponse))();
    const usersInfoResponseMarshaller = new (MarshalFrom(UsersInfoResponse))();

    const rightNow: Date = new Date(Date.now());

    const theSessionToken = new SessionToken(uuid());

    const theSession = new Session();
    theSession.state = SessionState.Active;
    theSession.xsrfToken = ('0' as any).repeat(64);
    theSession.agreedToCookiePolicy = false;
    theSession.timeCreated = rightNow;
    theSession.timeLastUpdated = rightNow;

    const theSessionWithAgreement = new Session();
    theSessionWithAgreement.state = SessionState.Active;
    theSessionWithAgreement.xsrfToken = ('0' as any).repeat(64);
    theSessionWithAgreement.agreedToCookiePolicy = true;
    theSessionWithAgreement.timeCreated = rightNow;
    theSessionWithAgreement.timeLastUpdated = rightNow;

    const theSessionTokenWithUser = new SessionToken(uuid(), 'x0bjohntok');

    const theSessionWithUser = new Session();
    theSessionWithUser.state = SessionState.ActiveAndLinkedWithUser;
    theSessionWithUser.xsrfToken = ('0' as any).repeat(64);
    theSessionWithUser.agreedToCookiePolicy = false;
    theSessionWithUser.timeCreated = rightNow;
    theSessionWithUser.timeLastUpdated = rightNow;
    theSessionWithUser.user = new PrivateUser();
    theSessionWithUser.user.id = 1;
    theSessionWithUser.user.state = UserState.Active;
    theSessionWithUser.user.role = Role.Regular;
    theSessionWithUser.user.name = 'John Doe';
    theSessionWithUser.user.pictureUri = 'https://example.com/picture.jpg';
    theSessionWithUser.user.language = 'en';
    theSessionWithUser.user.timeCreated = rightNow;
    theSessionWithUser.user.timeLastUpdated = rightNow;
    theSessionWithUser.user.agreedToCookiePolicy = false;
    theSessionWithUser.user.userIdHash = ('f' as any).repeat(64);

    const userInfoJohnDoe = new PublicUser();
    userInfoJohnDoe.id = 1;
    userInfoJohnDoe.state = UserState.Active;
    userInfoJohnDoe.role = Role.Regular;
    userInfoJohnDoe.name = 'John Doe';
    userInfoJohnDoe.pictureUri = 'https://example.com/picture1.jpg';
    userInfoJohnDoe.language = 'en';
    userInfoJohnDoe.timeCreated = rightNow;
    userInfoJohnDoe.timeLastUpdated = rightNow;

    const userInfoJaneDoe = new PublicUser();
    userInfoJaneDoe.id = 2;
    userInfoJaneDoe.state = UserState.Active;
    userInfoJaneDoe.role = Role.Regular;
    userInfoJaneDoe.name = 'Jane Doe';
    userInfoJaneDoe.pictureUri = 'https://example.com/picture2.jpg';
    userInfoJaneDoe.language = 'en';
    userInfoJaneDoe.timeCreated = rightNow;
    userInfoJaneDoe.timeLastUpdated = rightNow;

    const fetcher = td.object({
        fetch: (_u: string, _o: any) => { }
    });

    const response = td.object({
        ok: true,
        json: () => { }
    });

    afterEach('reset test doubles', () => {
        td.reset();
    });

    it('can be constructed', () => {
        const client = newIdentityClient(Env.Local, 'core', 'identity', fetcher as WebFetcher);

        expect(client).is.not.null;
        expect((client as any)._protocol).is.eql('http');
    });

    it('can be constructed in test', () => {
        const client = newIdentityClient(Env.Test, 'core', 'identity', fetcher as WebFetcher);

        expect(client).is.not.null;
        expect((client as any)._protocol).is.eql('http');
    });

    for (let env of [Env.Staging, Env.Prod]) {
        it(`can be constructed in non-local env=${env}`, () => {
            const client = newIdentityClient(env, 'core', 'identity', fetcher as WebFetcher);

            expect(client).is.not.null;
            expect((client as any)._protocol).is.eql('http');
        });
    }

    it('can attach a context', () => {
        const client = newIdentityClient(Env.Local, 'core', 'identity', fetcher as WebFetcher);
        const clientWithToken = client.withContext(theSessionToken);

        expect(clientWithToken).is.not.null;
    });

    describe('getOrCreateSession', () => {
        it('should return session token and session with no session info', async () => {
            const client = newIdentityClient(Env.Local, 'core', 'identity', fetcher as WebFetcher);

            const sessionAndTokenResponse = new SessionAndTokenResponse();
            sessionAndTokenResponse.sessionToken = theSessionToken;
            sessionAndTokenResponse.session = theSession;

            td.when(fetcher.fetch('http://identity/api/sessions', {
                method: 'POST',
                cache: 'no-cache',

                redirect: 'error',
                referrer: 'client',
                headers: {
                    'Origin': 'core'
                }
            })).thenReturn(response);
            td.when(response.json()).thenReturn(sessionAndTokenResponseMarshaller.pack(sessionAndTokenResponse));

            const [sessionToken, session] = await client.getOrCreateSession();

            expect(sessionToken).to.eql(theSessionToken);
            expect(session).to.eql(theSession);
        });

        it('should return session token and session with session info attached', async () => {
            const client = newIdentityClient(Env.Local, 'core', 'identity', fetcher as WebFetcher).withContext(theSessionToken);

            const sessionAndTokenResponse = new SessionAndTokenResponse();
            sessionAndTokenResponse.sessionToken = theSessionToken;
            sessionAndTokenResponse.session = theSession;

            td.when(fetcher.fetch('http://identity/api/sessions', {
                method: 'POST',
                cache: 'no-cache',
                redirect: 'error',
                referrer: 'client',
                headers: {
                    'Origin': 'core',
                    [SESSION_TOKEN_HEADER_NAME]: JSON.stringify(sessionTokenMarshaller.pack(theSessionToken))
                }
            })).thenReturn(response);
            td.when(response.json()).thenReturn(sessionAndTokenResponseMarshaller.pack(sessionAndTokenResponse));

            const [sessionToken, session] = await client.getOrCreateSession();

            expect(sessionToken).to.eql(theSessionToken);
            expect(session).to.eql(theSession);
        });

        testErrorPaths(c => c.getOrCreateSession());
        testJSONDecoding(c => c.getOrCreateSession());
    });

    describe('getSession', () => {
        it('should return session', async () => {
            const client = newIdentityClient(Env.Local, 'core', 'identity', fetcher as WebFetcher).withContext(theSessionToken);

            const sessionResponse = new SessionResponse();
            sessionResponse.session = theSession;

            td.when(fetcher.fetch('http://identity/api/sessions', {
                method: 'GET',
                cache: 'no-cache',
                redirect: 'error',
                referrer: 'client',
                headers: {
                    'Origin': 'core',
                    [SESSION_TOKEN_HEADER_NAME]: JSON.stringify(sessionTokenMarshaller.pack(theSessionToken))
                }
            })).thenReturn(response);
            td.when(response.json()).thenReturn(sessionResponseMarshaller.pack(sessionResponse));

            const session = await client.getSession();

            expect(session).to.eql(theSession);
        });

        testErrorPaths(c => c.getSession());
        testUnauthorized(c => c.getSession())
        testJSONDecoding(c => c.getSession());
    });

    describe('removeSession', () => {
        it('should remove session', async () => {
            const client = newIdentityClient(Env.Local, 'core', 'identity', fetcher as WebFetcher).withContext(theSessionToken);

            td.when(fetcher.fetch('http://identity/api/sessions', {
                method: 'DELETE',
                cache: 'no-cache',
                redirect: 'error',
                referrer: 'client',
                headers: {
                    'Origin': 'core',
                    [SESSION_TOKEN_HEADER_NAME]: JSON.stringify(sessionTokenMarshaller.pack(theSessionToken)),
                    [XSRF_TOKEN_HEADER_NAME]: theSession.xsrfToken
                }
            })).thenReturn({ ok: true });

            await client.removeSession(theSession);

            expect(true).to.be.true;
        });

        testErrorPaths(c => c.removeSession(theSession));
        testUnauthorized(c => c.removeSession(theSession))
    });

    describe('agreeToCookiePolicyForSession', () => {
        it('should return new session with agreement', async () => {
            const client = newIdentityClient(Env.Local, 'core', 'identity', fetcher as WebFetcher).withContext(theSessionToken);

            const sessionResponse = new SessionResponse();
            sessionResponse.session = theSessionWithAgreement;

            td.when(fetcher.fetch('http://identity/api/sessions/agree-to-cookie-policy', {
                method: 'POST',
                cache: 'no-cache',
                redirect: 'error',
                referrer: 'client',
                headers: {
                    'Origin': 'core',
                    [SESSION_TOKEN_HEADER_NAME]: JSON.stringify(sessionTokenMarshaller.pack(theSessionToken)),
                    [XSRF_TOKEN_HEADER_NAME]: theSession.xsrfToken
                }
            })).thenReturn(response);
            td.when(response.json()).thenReturn(sessionResponseMarshaller.pack(sessionResponse));

            const session = await client.agreeToCookiePolicyForSession(theSession);

            expect(session).to.eql(theSessionWithAgreement);
        });

        testErrorPaths(c => c.agreeToCookiePolicyForSession(theSession));
        testUnauthorized(c => c.agreeToCookiePolicyForSession(theSession));
        testJSONDecoding(c => c.agreeToCookiePolicyForSession(theSession));
    });

    describe('getOrCreateUserOnSession', () => {
        it('should return new session with a user', async () => {
            const client = newIdentityClient(Env.Local, 'core', 'identity', fetcher as WebFetcher).withContext(theSessionTokenWithUser);

            const sessionAndTokenResponse = new SessionAndTokenResponse();
            sessionAndTokenResponse.sessionToken = theSessionTokenWithUser;
            sessionAndTokenResponse.session = theSessionWithUser;

            td.when(fetcher.fetch('http://identity/api/users', {
                method: 'POST',
                cache: 'no-cache',
                redirect: 'error',
                referrer: 'client',
                headers: {
                    'Origin': 'core',
                    [SESSION_TOKEN_HEADER_NAME]: JSON.stringify(sessionTokenMarshaller.pack(theSessionTokenWithUser)),
                    [XSRF_TOKEN_HEADER_NAME]: theSession.xsrfToken
                }
            })).thenReturn(response);
            td.when(response.json()).thenReturn(sessionAndTokenResponseMarshaller.pack(sessionAndTokenResponse));

            const [sessionToken, session] = await client.getOrCreateUserOnSession(theSessionWithUser);

            expect(sessionToken).to.eql(theSessionTokenWithUser);
            expect(session).to.eql(theSessionWithUser);
        });

        testErrorPaths(c => c.getOrCreateUserOnSession(theSession));
        testUnauthorized(c => c.getOrCreateUserOnSession(theSession));
        testJSONDecoding(c => c.getOrCreateUserOnSession(theSession));
    });

    describe('getUserOnSession', () => {
        it('should return a session with a user', async () => {
            const client = newIdentityClient(Env.Local, 'core', 'identity', fetcher as WebFetcher).withContext(theSessionTokenWithUser);

            const sessionResponse = new SessionResponse();
            sessionResponse.session = theSessionWithUser;

            td.when(fetcher.fetch('http://identity/api/users', {
                method: 'GET',
                cache: 'no-cache',
                redirect: 'error',
                referrer: 'client',
                headers: {
                    'Origin': 'core',
                    [SESSION_TOKEN_HEADER_NAME]: JSON.stringify(sessionTokenMarshaller.pack(theSessionTokenWithUser))
                }
            })).thenReturn(response);
            td.when(response.json()).thenReturn(sessionResponseMarshaller.pack(sessionResponse));

            const session = await client.getUserOnSession();

            expect(session).to.eql(theSessionWithUser);
        });

        testErrorPaths(c => c.getUserOnSession());
        testUnauthorized(c => c.getUserOnSession());
        testJSONDecoding(c => c.getUserOnSession());
    });

    describe('getUsersInfo', () => {
        it('should return a set of users', async () => {
            const client = newIdentityClient(Env.Local, 'core', 'identity', fetcher as WebFetcher).withContext(theSessionToken);

            const usersInfoResponse = new UsersInfoResponse();
            usersInfoResponse.usersInfo = [userInfoJohnDoe, userInfoJaneDoe];

            td.when(fetcher.fetch('http://identity/api/users-info?ids=%5B1%2C2%5D', {
                method: 'GET',
                cache: 'no-cache',
                redirect: 'error',
                referrer: 'client',
                headers: {
                    'Origin': 'core',
                    [SESSION_TOKEN_HEADER_NAME]: JSON.stringify(sessionTokenMarshaller.pack(theSessionToken))
                }
            })).thenReturn(response);
            td.when(response.json()).thenReturn(usersInfoResponseMarshaller.pack(usersInfoResponse));

            const usersInfo = await client.getUsersInfo([1, 2]);

            expect(usersInfo).to.eql([userInfoJohnDoe, userInfoJaneDoe]);
        });

        it('should return a deduped set of users', async () => {
            const client = newIdentityClient(Env.Local, 'core', 'identity', fetcher as WebFetcher).withContext(theSessionToken);

            const usersInfoResponse = new UsersInfoResponse();
            usersInfoResponse.usersInfo = [userInfoJohnDoe, userInfoJaneDoe];

            td.when(fetcher.fetch('http://identity/api/users-info?ids=%5B1%2C2%5D', {
                method: 'GET',
                cache: 'no-cache',
                redirect: 'error',
                referrer: 'client',
                headers: {
                    'Origin': 'core',
                    [SESSION_TOKEN_HEADER_NAME]: JSON.stringify(sessionTokenMarshaller.pack(theSessionToken))
                }
            })).thenReturn(response);
            td.when(response.json()).thenReturn(usersInfoResponseMarshaller.pack(usersInfoResponse));

            const usersInfo = await client.getUsersInfo([1, 1, 2]);

            expect(usersInfo).to.eql([userInfoJohnDoe, userInfoJaneDoe]);
        });

        testErrorPaths(c => c.getUsersInfo([1, 2]));
        testJSONDecoding(c => c.getUsersInfo([1, 2]));
    });

    function testErrorPaths<T>(methodExtractor: (client: IdentityClient) => Promise<T>) {
        it('should throw when the fetch fails', async () => {
            const client = newIdentityClient(Env.Local, 'core', 'identity', fetcher as WebFetcher).withContext(theSessionToken);

            td.when(fetcher.fetch(td.matchers.isA(String), td.matchers.anything())).thenThrow(new Error('An error'));

            try {
                await methodExtractor(client);
                expect(true).to.be.false;
            } catch (e) {
                expect(e.message).to.eql('Request failed because \'Error: An error\'');
            }
        });

        it('should throw when the HTTP response was an error', async () => {
            const response = td.object({
                ok: false,
                status: HttpStatus.BAD_REQUEST,
                json: () => { }
            })
            const client = newIdentityClient(Env.Local, 'core', 'identity', fetcher as WebFetcher);

            td.when(fetcher.fetch(td.matchers.isA(String), td.matchers.anything())).thenReturn(response);

            try {
                await methodExtractor(client);
                expect(true).to.be.false;
            } catch (e) {
                expect(e.message).to.eql('Service response 400');
            }
        });
    }

    function testUnauthorized<T>(methodExtractor: (client: IdentityClient) => Promise<T>) {
        it('should throw when the HTTP response was an UNAUTHORIZED error', async () => {
            const response = td.object({
                ok: false,
                status: HttpStatus.UNAUTHORIZED,
                json: () => { }
            })
            const client = newIdentityClient(Env.Local, 'core', 'identity', fetcher as WebFetcher);

            td.when(fetcher.fetch(td.matchers.isA(String), td.matchers.anything())).thenReturn(response);

            try {
                await methodExtractor(client);
                expect(true).to.be.false;
            } catch (e) {
                expect(e.message).to.eql('User is not authorized');
            }
        });
    }

    function testJSONDecoding<T>(methodExtractor: (client: IdentityClient) => Promise<T>) {
        it('should throw when the json cannot be obtained', async () => {
            const client = newIdentityClient(Env.Local, 'core', 'identity', fetcher as WebFetcher);

            td.when(fetcher.fetch(td.matchers.isA(String), td.matchers.anything())).thenReturn(response);
            td.when(response.json()).thenThrow(new Error('Bad JSON'));

            try {
                await methodExtractor(client);
                expect(true).to.be.false;
            } catch (e) {
                expect(e.message).to.eql('JSON decoding error because \'Error: Bad JSON\'');
            }
        });

        it('should throw when the response json cannot be decoded', async () => {
            const client = newIdentityClient(Env.Local, 'core', 'identity', fetcher as WebFetcher);

            td.when(fetcher.fetch(td.matchers.isA(String), td.matchers.anything())).thenReturn(response);
            td.when(response.json()).thenReturn('FOO');

            try {
                await methodExtractor(client);
                expect(true).to.be.false;
            } catch (e) {
                expect(e.message).to.eql('JSON decoding error because \'ExtractError: Expected an object\'');
            }
        });
    }
});
