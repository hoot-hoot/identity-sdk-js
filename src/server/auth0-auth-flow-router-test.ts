import { expect } from 'chai'
import * as express from 'express'
import * as HttpStatus from 'http-status-codes'
import 'mocha'
import { MarshalFrom } from 'raynor'
import * as serializeJavascript from 'serialize-javascript'
import * as td from 'testdouble'
import { agent } from 'supertest'
import * as uuid from 'uuid'

import { Env, isOnServer, WebFetcher } from '@truesparrow/common-js'
import { newLocalCommonServerMiddleware } from '@truesparrow/common-server-js'

import {
    Auth0AuthorizeRedirectInfo,
    Auth0AuthorizeRedirectInfoMarshaller,
    Auth0AuthorizationCodeMarshaller,
    Auth0AccessTokenMarshaller,
    newAuth0AuthFlowRouter
} from './auth0-auth-flow-router'
import {
    PathMatch,
    PostLoginRedirectInfo,
    PostLoginRedirectInfoMarshaller
} from '../auth-flow'
import {
    Auth0ServerConfig
} from '../auth0'
import {
    IdentityClient,
    IdentityError,
    SESSION_TOKEN_COOKIE_NAME,
    UnauthorizedIdentityError
} from '../client'
import { PrivateUser, Role, Session, SessionState, UserState } from '../entities'
import { SessionToken } from '../session-token'


describe('Auth0AccessTokenMarshaller', () => {
    const auth0AccessTokens = [
        'foogazi',
        'aGoodToken',
        'A-Good-Token',
        'A_Good_Token'
    ];

    const emptyAuth0AccessTokens = [
        ''
    ];

    const badAuth0AccessTokens = [
        '$',
        '  ',
        'a.bad.token'
    ];

    describe('extract', () => {
        for (let accessToken of auth0AccessTokens) {
            it(`should extract "${accessToken}"`, () => {
                const marshaller = new Auth0AccessTokenMarshaller();

                expect(marshaller.extract(accessToken)).to.eql(accessToken);
            });
        }

        for (let accessToken of emptyAuth0AccessTokens) {
            it(`should throw for empty "${accessToken}"`, () => {
                const marshaller = new Auth0AccessTokenMarshaller();

                expect(() => marshaller.extract(accessToken)).to.throw('Expected a string to be non-empty');
            });
        }

        for (let accessToken of badAuth0AccessTokens) {
            it(`should throw for bad "${accessToken}"`, () => {
                const marshaller = new Auth0AccessTokenMarshaller();

                expect(() => marshaller.extract(accessToken)).to.throw('Should only contain alphanumerics');
            });
        }
    });

    describe('pack', () => {
        for (let accessToken of auth0AccessTokens) {
            it(`should produce the same input "${accessToken}"`, () => {
                const marshaller = new Auth0AccessTokenMarshaller();

                expect(marshaller.pack(accessToken)).to.eql(accessToken);
            });
        }
    });
});


describe('Auth0AuthorizationCodeMarshaller', () => {
    const auth0AuthorizationCode = [
        'foogazi',
        'aGoodToken',
        'A-Good-Token',
        'A_Good_Token'
    ];

    const emptyAuth0AuthorizationCodes = [
        ''
    ];

    const badAuth0AuthorizationCodes = [
        '$',
        '  ',
        'a.bad.token'
    ];

    describe('extract', () => {
        for (let accessToken of auth0AuthorizationCode) {
            it(`should extract "${accessToken}"`, () => {
                const marshaller = new Auth0AuthorizationCodeMarshaller();

                expect(marshaller.extract(accessToken)).to.eql(accessToken);
            });
        }

        for (let accessToken of emptyAuth0AuthorizationCodes) {
            it(`should throw for empty "${accessToken}"`, () => {
                const marshaller = new Auth0AuthorizationCodeMarshaller();

                expect(() => marshaller.extract(accessToken)).to.throw('Expected a string to be non-empty');
            });
        }

        for (let accessToken of badAuth0AuthorizationCodes) {
            it(`should throw for bad "${accessToken}"`, () => {
                const marshaller = new Auth0AuthorizationCodeMarshaller();

                expect(() => marshaller.extract(accessToken)).to.throw('Should only contain alphanumerics');
            });
        }
    });

    describe('pack', () => {
        for (let accessToken of auth0AuthorizationCode) {
            it(`should produce the same input "${accessToken}"`, () => {
                const marshaller = new Auth0AuthorizationCodeMarshaller();

                expect(marshaller.pack(accessToken)).to.eql(accessToken);
            });
        }
    });
});


describe('Auth0AuthorizeRedirectInfo', () => {
    it('can be constructed', () => {
        const redirectInfo = new Auth0AuthorizeRedirectInfo('a-code', new PostLoginRedirectInfo('/'));

        expect(redirectInfo.authorizationCode).to.eql('a-code');
        expect(redirectInfo.state).to.eql(new PostLoginRedirectInfo('/'));
    });

    describe('marshalling', () => {
        const allowedPaths: PathMatch[] = [
            { path: '/', mode: 'full' },
            { path: '/admin', mode: 'full' },
            { path: '/admin/', mode: 'prefix' }
        ];
        const auth0AuthorizeRedirectInfos = [
            [{ code: 'abcabc', state: quickEncode({ path: '/' }) }, new Auth0AuthorizeRedirectInfo('abcabc', new PostLoginRedirectInfo('/'))],
            [{ code: 'abcabc', state: quickEncode({ path: '/admin' }) }, new Auth0AuthorizeRedirectInfo('abcabc', new PostLoginRedirectInfo('/admin'))],
            [{ code: 'abcabc', state: quickEncode({ path: '/admin/foo' }) }, new Auth0AuthorizeRedirectInfo('abcabc', new PostLoginRedirectInfo('/admin/foo'))],
            [{ code: 'abcabc', state: quickEncode({ path: '/admin/foo?id=10' }) }, new Auth0AuthorizeRedirectInfo('abcabc', new PostLoginRedirectInfo('/admin/foo?id=10'))]
        ];

        const badAuth0AuthorizeRedirectInfos = [
            { code: 'abcabc', state: quickEncode({ path: '/a-bad-path' }) },
            { code: 'abcabc', state: quickEncode({ path: 'admin' }) }
        ];

        describe('extract', () => {
            for (let [raw, extracted] of auth0AuthorizeRedirectInfos) {
                it(`should extract ${JSON.stringify(raw)}`, () => {
                    const marshaller = new (Auth0AuthorizeRedirectInfoMarshaller(allowedPaths))();
                    expect(marshaller.extract(raw)).to.eql(extracted);
                })
            }

            for (let example of badAuth0AuthorizeRedirectInfos) {
                it(`should throw for ${JSON.stringify(example)}`, () => {
                    const marshaller = new (Auth0AuthorizeRedirectInfoMarshaller(allowedPaths))();
                    expect(() => marshaller.extract(example)).to.throw;
                });
            }
        });

        describe('pack', () => {
            for (let [raw, extracted] of auth0AuthorizeRedirectInfos) {
                it(`should produce the same input for ${JSON.stringify(raw)}`, () => {
                    const marshaller = new (Auth0AuthorizeRedirectInfoMarshaller(allowedPaths))();
                    expect(marshaller.pack(extracted as Auth0AuthorizeRedirectInfo)).to.eql(raw);
                });
            }
        });

        describe('extract and pack', () => {
            for (let [example] of auth0AuthorizeRedirectInfos) {
                it(`should be opposites ${JSON.stringify(example)}`, () => {
                    const marshaller = new (Auth0AuthorizeRedirectInfoMarshaller(allowedPaths))();

                    const raw = example;
                    const extracted = marshaller.extract(raw);
                    const packed = marshaller.pack(extracted);

                    expect(packed).to.eql(raw);
                });
            }
        });

        function quickEncode(obj: any): string {
            return encodeURIComponent(encodeURIComponent(serializeJavascript(obj)));
        }
    });
});


describe('Auth0AuthFlowRouter', () => {
    const allowedPaths: PathMatch[] = [
        { path: '/', mode: 'full' },
        { path: '/admin', mode: 'full' },
        { path: '/admin/', mode: 'prefix' }
    ];

    const auth0ServerConfig: Auth0ServerConfig = {
        clientId: 'foo',
        clientSecret: 'bar',
        domain: 'some-domain',
        loginCallbackUri: '/login'
    };

    const sessionTokenMarshaller = new (MarshalFrom(SessionToken))();
    const postLoginRedirectInfoMarshaller = new (PostLoginRedirectInfoMarshaller(allowedPaths))();

    const rightNow: Date = new Date(Date.UTC(2017, 11, 24));

    const theSessionToken = new SessionToken(uuid());

    const theSession = new Session();
    theSession.state = SessionState.Active;
    theSession.xsrfToken = ('0' as any).repeat(64);
    theSession.agreedToCookiePolicy = false;
    theSession.timeCreated = rightNow;
    theSession.timeLastUpdated = rightNow;

    const theSessionTokenWithUser = new SessionToken(theSessionToken.sessionId, 'x0bjohntok');
    const theOtherSessionTokenWithUser = new SessionToken(theSessionToken.sessionId, 'x0bjohntok2');

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

    afterEach('reset test doubles', () => {
        td.reset();
    });

    describe('/login', () => {
        const webFetcher = td.object({
            fetch: (_u: string, _o: any) => { }
        });
        const identityClient = td.object({
            withContext: (_t: SessionToken) => { },
            getSession: () => { },
            getUserOnSession: () => { },
            getOrCreateUserOnSession: (_s: Session) => { }
        });

        for (let env of [Env.Local, Env.Staging, Env.Test, Env.Prod]) {
            it(`should work with a session env=${env}`, async () => {
                const response = td.object({
                    ok: true,
                    json: () => { }
                });

                const appAgent = buildAppAgent(env, webFetcher as WebFetcher, identityClient as IdentityClient);

                td.when(webFetcher.fetch('https://some-domain/oauth/token', {
                    method: 'POST',
                    mode: 'cors',
                    cache: 'no-cache',
                    redirect: 'error',
                    referrer: 'client',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        grant_type: 'authorization_code',
                        client_id: 'foo',
                        client_secret: 'bar',
                        code: 'some_code',
                        redirect_uri: '/login'
                    })
                })).thenReturn(response);
                td.when(response.json()).thenReturn({ access_token: 'x0bjohntok' });

                td.when(identityClient.withContext(theSessionToken)).thenReturn(identityClient);
                td.when(identityClient.getSession()).thenResolve(theSession);
                td.when(identityClient.withContext(theSessionTokenWithUser)).thenReturn(identityClient);
                td.when(identityClient.getOrCreateUserOnSession(theSession)).thenReturn([theSessionTokenWithUser, theSessionWithUser]);

                await appAgent
                    .get('/login?code=some_code&state=' + postLoginRedirectInfoMarshaller.pack(new PostLoginRedirectInfo('/admin')))
                    .set('Cookie', `${SESSION_TOKEN_COOKIE_NAME}=${encodeURIComponent('j:' + JSON.stringify(sessionTokenMarshaller.pack(theSessionToken)))}`)
                    .expect(HttpStatus.MOVED_TEMPORARILY)
                    .then(response => {
                        expect(response.header).contains.keys('set-cookie', 'location', 'content-type');
                        expect(response.header['set-cookie']).to.have.length(2);
                        expect(response.header['set-cookie'][0]).to.match(
                            new RegExp(`${SESSION_TOKEN_COOKIE_NAME}=${encodeURIComponent('j:' + JSON.stringify(sessionTokenMarshaller.pack(theSessionToken)))}; Path=/; Expires=.*GMT; HttpOnly;${isOnServer(env) ? " Secure;" : ""} SameSite=Lax`));
                        expect(response.header['set-cookie'][1]).to.match(
                            new RegExp(`${SESSION_TOKEN_COOKIE_NAME}=${encodeURIComponent('j:' + JSON.stringify(sessionTokenMarshaller.pack(theSessionTokenWithUser)))}; Path=/; Expires=.*GMT; HttpOnly;${isOnServer(env) ? " Secure;" : ""} SameSite=Lax`));
                        expect(response.header['location']).to.eql('/admin');
                        expect(response.header['content-type']).to.eql('text/plain; charset=utf-8');
                        expect(response.text).to.eql('Found. Redirecting to /admin');
                        expect(response.charset).to.eql('utf-8');
                        expect(response.type).to.eql('text/plain');
                    });
            });

            it('should work with a session with a user', async () => {
                const response = td.object({
                    ok: true,
                    json: () => { }
                });

                const appAgent = buildAppAgent(env, webFetcher as WebFetcher, identityClient as IdentityClient);

                td.when(webFetcher.fetch('https://some-domain/oauth/token', {
                    method: 'POST',
                    mode: 'cors',
                    cache: 'no-cache',
                    redirect: 'error',
                    referrer: 'client',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        grant_type: 'authorization_code',
                        client_id: 'foo',
                        client_secret: 'bar',
                        code: 'some_code',
                        redirect_uri: '/login'
                    })
                })).thenReturn(response);
                td.when(response.json()).thenReturn({ access_token: 'x0bjohntok' });

                td.when(identityClient.withContext(theSessionTokenWithUser)).thenReturn(identityClient);
                td.when(identityClient.getUserOnSession()).thenResolve(theSessionWithUser);
                td.when(identityClient.withContext(theSessionTokenWithUser)).thenReturn(identityClient);
                td.when(identityClient.getOrCreateUserOnSession(theSessionWithUser)).thenReturn([theSessionTokenWithUser, theSessionWithUser]);

                await appAgent
                    .get('/login?code=some_code&state=' + postLoginRedirectInfoMarshaller.pack(new PostLoginRedirectInfo('/admin')))
                    .set('Cookie', `${SESSION_TOKEN_COOKIE_NAME}=${encodeURIComponent('j:' + JSON.stringify(sessionTokenMarshaller.pack(theSessionTokenWithUser)))}`)
                    .expect(HttpStatus.MOVED_TEMPORARILY)
                    .then(response => {
                        expect(response.header).contains.keys('set-cookie', 'location', 'content-type');
                        expect(response.header['set-cookie']).to.have.length(2);
                        expect(response.header['set-cookie'][0]).to.match(
                            new RegExp(`${SESSION_TOKEN_COOKIE_NAME}=${encodeURIComponent('j:' + JSON.stringify(sessionTokenMarshaller.pack(theSessionTokenWithUser)))}; Path=/; Expires=.*GMT; HttpOnly;${isOnServer(env) ? " Secure;" : ""} SameSite=Lax`));
                        expect(response.header['set-cookie'][1]).to.match(
                            new RegExp(`${SESSION_TOKEN_COOKIE_NAME}=${encodeURIComponent('j:' + JSON.stringify(sessionTokenMarshaller.pack(theSessionTokenWithUser)))}; Path=/; Expires=.*GMT; HttpOnly;${isOnServer(env) ? " Secure;" : ""} SameSite=Lax`));
                        expect(response.header['location']).to.eql('/admin');
                        expect(response.header['content-type']).to.eql('text/plain; charset=utf-8');
                        expect(response.text).to.eql('Found. Redirecting to /admin');
                        expect(response.charset).to.eql('utf-8');
                        expect(response.type).to.eql('text/plain');
                    });
            });

            it('should work with a session with a user when we get a new token', async () => {
                const response = td.object({
                    ok: true,
                    json: () => { }
                });

                const appAgent = buildAppAgent(env, webFetcher as WebFetcher, identityClient as IdentityClient);

                td.when(webFetcher.fetch('https://some-domain/oauth/token', {
                    method: 'POST',
                    mode: 'cors',
                    cache: 'no-cache',
                    redirect: 'error',
                    referrer: 'client',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        grant_type: 'authorization_code',
                        client_id: 'foo',
                        client_secret: 'bar',
                        code: 'some_code',
                        redirect_uri: '/login'
                    })
                })).thenReturn(response);
                td.when(response.json()).thenReturn({ access_token: 'x0bjohntok2' });

                td.when(identityClient.withContext(theSessionTokenWithUser)).thenReturn(identityClient);
                td.when(identityClient.getUserOnSession()).thenResolve(theSessionWithUser);
                td.when(identityClient.withContext(theOtherSessionTokenWithUser)).thenReturn(identityClient);
                td.when(identityClient.getOrCreateUserOnSession(theSessionWithUser)).thenReturn([theOtherSessionTokenWithUser, theSessionWithUser]);

                await appAgent
                    .get('/login?code=some_code&state=' + postLoginRedirectInfoMarshaller.pack(new PostLoginRedirectInfo('/admin')))
                    .set('Cookie', `${SESSION_TOKEN_COOKIE_NAME}=${encodeURIComponent('j:' + JSON.stringify(sessionTokenMarshaller.pack(theSessionTokenWithUser)))}`)
                    .expect(HttpStatus.MOVED_TEMPORARILY)
                    .then(response => {
                        expect(response.header).contains.keys('set-cookie', 'location', 'content-type');
                        expect(response.header['set-cookie']).to.have.length(2);
                        expect(response.header['set-cookie'][0]).to.match(
                            new RegExp(`${SESSION_TOKEN_COOKIE_NAME}=${encodeURIComponent('j:' + JSON.stringify(sessionTokenMarshaller.pack(theSessionTokenWithUser)))}; Path=/; Expires=.*GMT; HttpOnly;${isOnServer(env) ? " Secure;" : ""} SameSite=Lax`));
                        expect(response.header['set-cookie'][1]).to.match(
                            new RegExp(`${SESSION_TOKEN_COOKIE_NAME}=${encodeURIComponent('j:' + JSON.stringify(sessionTokenMarshaller.pack(theOtherSessionTokenWithUser)))}; Path=/; Expires=.*GMT; HttpOnly;${isOnServer(env) ? " Secure;" : ""} SameSite=Lax`));
                        expect(response.header['location']).to.eql('/admin');
                        expect(response.header['content-type']).to.eql('text/plain; charset=utf-8');
                        expect(response.text).to.eql('Found. Redirecting to /admin');
                        expect(response.charset).to.eql('utf-8');
                        expect(response.type).to.eql('text/plain');
                    });
            });

            for (let [text, cookieData] of [
                ['when the session token is not present', ''],
                ['when the session token is bad', `${SESSION_TOKEN_COOKIE_NAME}=bad-token`],
                ['when the session token has bad data', `${SESSION_TOKEN_COOKIE_NAME}=${JSON.stringify({ foo: "bar" })}`],
            ]) {
                it(`return BAD_REQUEST ${text}`, async () => {
                    const appAgent = buildAppAgent(env, webFetcher as WebFetcher, identityClient as IdentityClient);

                    await appAgent
                        .get('/login?code=some_code&state=' + postLoginRedirectInfoMarshaller.pack(new PostLoginRedirectInfo('/admin')))
                        .set('Cookie', cookieData)
                        .expect(HttpStatus.BAD_REQUEST)
                        .then(response => {
                            expect(response.text).to.be.empty;
                            td.verify(identityClient.getOrCreateUserOnSession(theSession), { times: 0 });
                        });
                });
            }

            for (let [text, error, statusCode] of [
                ['UNAUTHORIZED when the identity service does not accept the user', new UnauthorizedIdentityError('Unauthorized'), HttpStatus.UNAUTHORIZED],
                ['BAD_GATEWAY when the identity service errors', new IdentityError('Error'), HttpStatus.BAD_GATEWAY],
                ['INTERNAL_SERVER_ERROR when there is another error', new Error('Bad error'), HttpStatus.INTERNAL_SERVER_ERROR]
            ]) {
                it(`when the identity retrieval fails it should return ${text}`, async () => {
                    const appAgent = buildAppAgent(env, webFetcher as WebFetcher, identityClient as IdentityClient);

                    td.when(identityClient.withContext(theSessionToken)).thenReturn(identityClient);
                    td.when(identityClient.getSession()).thenReject(error as Error);

                    await appAgent
                        .get('/login?code=some_code&state=' + postLoginRedirectInfoMarshaller.pack(new PostLoginRedirectInfo('/admin')))
                        .set('Cookie', `${SESSION_TOKEN_COOKIE_NAME}=${encodeURIComponent('j:' + JSON.stringify(sessionTokenMarshaller.pack(theSessionToken)))}`)
                        .expect(statusCode)
                        .then(response => {
                            expect(response.text).to.be.empty;
                            td.verify(identityClient.getOrCreateUserOnSession(theSession), { times: 0 });
                        });
                });
            }

            for (let params of [
                '',
                '?code=some_code',
                '?state=' + postLoginRedirectInfoMarshaller.pack(new PostLoginRedirectInfo('/admin')),
                '?code=()',
                '?code=some_code&state=foo',
                '?code=some_code&state=' + postLoginRedirectInfoMarshaller.pack(new PostLoginRedirectInfo('/adminx')),
            ]) {
                it(`should return BAD_REQUEST when the query parameters are bad for "${params}"`, async () => {
                    const appAgent = buildAppAgent(env, webFetcher as WebFetcher, identityClient as IdentityClient);

                    td.when(identityClient.withContext(theSessionToken)).thenReturn(identityClient);
                    td.when(identityClient.getSession()).thenResolve(theSession);

                    await appAgent.get('/login' + params)
                        .set('Cookie', `${SESSION_TOKEN_COOKIE_NAME}=${encodeURIComponent('j:' + JSON.stringify(sessionTokenMarshaller.pack(theSessionToken)))}`)
                        .expect(HttpStatus.BAD_REQUEST)
                        .then(response => {
                            expect(response.text).to.be.empty;
                        });
                });
            }

            it('should return BAD_GATEWAY when the fetch fails', async () => {
                const appAgent = buildAppAgent(env, webFetcher as WebFetcher, identityClient as IdentityClient);

                td.when(webFetcher.fetch('https://some-domain/oauth/token', {
                    method: 'POST',
                    mode: 'cors',
                    cache: 'no-cache',
                    redirect: 'error',
                    referrer: 'client',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        grant_type: 'authorization_code',
                        client_id: 'foo',
                        client_secret: 'bar',
                        code: 'some_code',
                        redirect_uri: '/login'
                    })
                })).thenThrow(new Error('Something bad happened'));

                td.when(identityClient.withContext(theSessionToken)).thenReturn(identityClient);
                td.when(identityClient.getSession()).thenResolve(theSession);

                await appAgent
                    .get('/login?code=some_code&state=' + postLoginRedirectInfoMarshaller.pack(new PostLoginRedirectInfo('/admin')))
                    .set('Cookie', `${SESSION_TOKEN_COOKIE_NAME}=${encodeURIComponent('j:' + JSON.stringify(sessionTokenMarshaller.pack(theSessionToken)))}`)
                    .expect(HttpStatus.BAD_GATEWAY)
                    .then(response => {
                        expect(response.text).to.be.empty;
                    });
            });

            it('should return BAD_GATEWAY when the fetch has a problem', async () => {
                const response = td.object({
                    ok: false,
                    status: HttpStatus.BAD_GATEWAY
                });

                const appAgent = buildAppAgent(env, webFetcher as WebFetcher, identityClient as IdentityClient);

                td.when(webFetcher.fetch('https://some-domain/oauth/token', {
                    method: 'POST',
                    mode: 'cors',
                    cache: 'no-cache',
                    redirect: 'error',
                    referrer: 'client',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        grant_type: 'authorization_code',
                        client_id: 'foo',
                        client_secret: 'bar',
                        code: 'some_code',
                        redirect_uri: '/login'
                    })
                })).thenReturn(response);

                td.when(identityClient.withContext(theSessionToken)).thenReturn(identityClient);
                td.when(identityClient.getSession()).thenResolve(theSession);

                await appAgent
                    .get('/login?code=some_code&state=' + postLoginRedirectInfoMarshaller.pack(new PostLoginRedirectInfo('/admin')))
                    .set('Cookie', `${SESSION_TOKEN_COOKIE_NAME}=${encodeURIComponent('j:' + JSON.stringify(sessionTokenMarshaller.pack(theSessionToken)))}`)
                    .expect(HttpStatus.BAD_GATEWAY)
                    .then(response => {
                        expect(response.text).to.be.empty;
                    });
            });

            it('should return INTERNAL_SERVER_ERROR when the fetched Auth0 data cannot be decoded', async () => {
                const response = td.object({
                    ok: true,
                    json: () => { }
                });

                const appAgent = buildAppAgent(env, webFetcher as WebFetcher, identityClient as IdentityClient);

                td.when(webFetcher.fetch('https://some-domain/oauth/token', {
                    method: 'POST',
                    mode: 'cors',
                    cache: 'no-cache',
                    redirect: 'error',
                    referrer: 'client',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        grant_type: 'authorization_code',
                        client_id: 'foo',
                        client_secret: 'bar',
                        code: 'some_code',
                        redirect_uri: '/login'
                    })
                })).thenReturn(response);
                td.when(response.json()).thenReturn({ not: "good" });

                td.when(identityClient.withContext(theSessionToken)).thenReturn(identityClient);
                td.when(identityClient.getSession()).thenResolve(theSession);

                await appAgent
                    .get('/login?code=some_code&state=' + postLoginRedirectInfoMarshaller.pack(new PostLoginRedirectInfo('/admin')))
                    .set('Cookie', `${SESSION_TOKEN_COOKIE_NAME}=${encodeURIComponent('j:' + JSON.stringify(sessionTokenMarshaller.pack(theSessionToken)))}`)
                    .expect(HttpStatus.INTERNAL_SERVER_ERROR)
                    .then(response => {
                        expect(response.text).to.be.empty;
                    });
            });

            for (let [text, error, statusCode] of [
                ['UNAUTHORIZED when the identity service does not accept the user', new UnauthorizedIdentityError('Unauthorized'), HttpStatus.UNAUTHORIZED],
                ['BAD_GATEWAY when the identity service errors', new IdentityError('Error'), HttpStatus.BAD_GATEWAY],
                ['INTERNAL_SERVER_ERROR when there is another error', new Error('Bad error'), HttpStatus.INTERNAL_SERVER_ERROR]
            ]) {
                it(`when the user creation fails it should return ${text}`, async () => {
                    const response = td.object({
                        ok: true,
                        json: () => { }
                    });

                    const appAgent = buildAppAgent(env, webFetcher as WebFetcher, identityClient as IdentityClient);

                    td.when(webFetcher.fetch('https://some-domain/oauth/token', {
                        method: 'POST',
                        mode: 'cors',
                        cache: 'no-cache',
                        redirect: 'error',
                        referrer: 'client',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            grant_type: 'authorization_code',
                            client_id: 'foo',
                            client_secret: 'bar',
                            code: 'some_code',
                            redirect_uri: '/login'
                        })
                    })).thenReturn(response);
                    td.when(response.json()).thenReturn({ access_token: 'x0bjohntok' });

                    td.when(identityClient.withContext(theSessionToken)).thenReturn(identityClient);
                    td.when(identityClient.getSession()).thenResolve(theSession);
                    td.when(identityClient.withContext(theSessionTokenWithUser)).thenReturn(identityClient);
                    td.when(identityClient.getOrCreateUserOnSession(theSession)).thenReject(error as Error);

                    await appAgent
                        .get('/login?code=some_code&state=' + postLoginRedirectInfoMarshaller.pack(new PostLoginRedirectInfo('/admin')))
                        .set('Cookie', `${SESSION_TOKEN_COOKIE_NAME}=${encodeURIComponent('j:' + JSON.stringify(sessionTokenMarshaller.pack(theSessionToken)))}`)
                        .expect(statusCode)
                        .then(response => {
                            expect(response.text).to.be.empty;
                        });
                });
            }
        }
    });

    describe('/logout', () => {
        const webFetcher = td.object({
            fetch: (_u: string, _o: any) => { }
        });
        const identityClient = td.object({
            withContext: (_t: SessionToken) => { },
            getUserOnSession: () => { },
            removeSession: (_s: Session) => { }
        });

        for (let env of [Env.Local, Env.Test, Env.Staging, Env.Prod]) {
            it('should work with a session and user', async () => {
                const appAgent = buildAppAgent(env, webFetcher as WebFetcher, identityClient as IdentityClient);

                td.when(identityClient.withContext(theSessionTokenWithUser)).thenReturn(identityClient);
                td.when(identityClient.getUserOnSession()).thenResolve(theSessionWithUser);

                await appAgent
                    .get('/logout')
                    .set('Cookie', `${SESSION_TOKEN_COOKIE_NAME}=${encodeURIComponent('j:' + JSON.stringify(sessionTokenMarshaller.pack(theSessionTokenWithUser)))}`)
                    .expect(HttpStatus.MOVED_TEMPORARILY)
                    .then(response => {
                        expect(response.header).contains.keys('set-cookie', 'location', 'content-type');
                        expect(response.header['set-cookie']).to.have.length(2);
                        expect(response.header['set-cookie'][0]).to.match(
                            new RegExp(`${SESSION_TOKEN_COOKIE_NAME}=${encodeURIComponent('j:' + JSON.stringify(sessionTokenMarshaller.pack(theSessionTokenWithUser)))}; Path=/; Expires=.*GMT; HttpOnly;${isOnServer(env) ? " Secure;" : ""} SameSite=Lax`));
                        expect(response.header['set-cookie'][1]).to.match(
                            new RegExp(`${SESSION_TOKEN_COOKIE_NAME}=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly`));
                        expect(response.header['location']).to.eql('/');
                        expect(response.header['content-type']).to.eql('text/plain; charset=utf-8');
                        expect(response.text).to.eql('Found. Redirecting to /');
                        expect(response.charset).to.eql('utf-8');
                        expect(response.type).to.eql('text/plain');

                        td.verify(identityClient.removeSession(theSessionWithUser));
                    });
            });

            for (let [text, cookieData] of [
                ['when the session token is not present', ''],
                ['when the session token is bad', `${SESSION_TOKEN_COOKIE_NAME}=bad-token`],
                ['when the session token has bad data', `${SESSION_TOKEN_COOKIE_NAME}=${JSON.stringify({ foo: "bar" })}`],
                ['when the session token does not contain user info', `${SESSION_TOKEN_COOKIE_NAME}=${encodeURIComponent('j:' + JSON.stringify(sessionTokenMarshaller.pack(theSessionToken)))}`]
            ]) {
                it(`return BAD_REQUEST ${text}`, async () => {
                    const appAgent = buildAppAgent(env, webFetcher as WebFetcher, identityClient as IdentityClient);

                    await appAgent
                        .get('/logout')
                        .set('Cookie', cookieData)
                        .expect(HttpStatus.BAD_REQUEST)
                        .then(response => {
                            expect(response.text).to.be.empty;
                            td.verify(identityClient.removeSession(theSessionWithUser), { times: 0 });
                        });
                });
            }

            for (let [text, error, statusCode] of [
                ['UNAUTHORIZED when the identity service does not accept the user', new UnauthorizedIdentityError('Unauthorized'), HttpStatus.UNAUTHORIZED],
                ['BAD_GATEWAY when the identity service errors', new IdentityError('Error'), HttpStatus.BAD_GATEWAY],
                ['INTERNAL_SERVER_ERROR when there is another error', new Error('Bad error'), HttpStatus.INTERNAL_SERVER_ERROR]
            ]) {
                it(`when the identity retrieval fails it should return ${text}`, async () => {
                    const appAgent = buildAppAgent(env, webFetcher as WebFetcher, identityClient as IdentityClient);

                    td.when(identityClient.withContext(theSessionTokenWithUser)).thenReturn(identityClient);
                    td.when(identityClient.getUserOnSession()).thenReject(error as Error);

                    await appAgent
                        .get('/logout')
                        .set('Cookie', `${SESSION_TOKEN_COOKIE_NAME}=${encodeURIComponent('j:' + JSON.stringify(sessionTokenMarshaller.pack(theSessionTokenWithUser)))}`)
                        .expect(statusCode)
                        .then(response => {
                            expect(response.text).to.be.empty;
                            td.verify(identityClient.removeSession(theSessionWithUser), { times: 0 });
                        });
                });
            }

            for (let [text, error, statusCode] of [
                ['UNAUTHORIZED when the identity service does not accept the user', new UnauthorizedIdentityError('Unauthorized'), HttpStatus.UNAUTHORIZED],
                ['BAD_GATEWAY when the identity service errors', new IdentityError('Error'), HttpStatus.BAD_GATEWAY],
                ['INTERNAL_SERVER_ERROR when there is another error', new Error('Bad error'), HttpStatus.INTERNAL_SERVER_ERROR]
            ]) {
                it(`when the identity removal fails it should return ${text}`, async () => {
                    const appAgent = buildAppAgent(env, webFetcher as WebFetcher, identityClient as IdentityClient);

                    td.when(identityClient.withContext(theSessionTokenWithUser)).thenReturn(identityClient);
                    td.when(identityClient.getUserOnSession()).thenResolve(theSessionWithUser);
                    td.when(identityClient.removeSession(theSessionWithUser)).thenThrow(error as Error);

                    await appAgent
                        .get('/logout')
                        .set('Cookie', `${SESSION_TOKEN_COOKIE_NAME}=${encodeURIComponent('j:' + JSON.stringify(sessionTokenMarshaller.pack(theSessionTokenWithUser)))}`)
                        .expect(statusCode)
                        .then(response => {
                            expect(response.text).to.be.empty;
                        });
                });
            }
        }
    });

    function buildAppAgent(env: Env, webFetcher: WebFetcher, identityClient: IdentityClient) {
        const router = newAuth0AuthFlowRouter(env, allowedPaths, auth0ServerConfig, webFetcher, identityClient);
        const app = express();
        app.use(newLocalCommonServerMiddleware('test', Env.Local, true));
        app.use(router);

        return agent(app);
    }
});
