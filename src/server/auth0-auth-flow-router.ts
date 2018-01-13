/** Defines a router which implements the auth flow via [Auth0]{@link https://auth0.com}. */

/** Imports. Also so typedoc works correctly. */
import { wrap } from 'async-middleware'
import * as express from 'express'
import * as HttpStatus from 'http-status-codes'
import * as r from 'raynor'
import { ExtractError, MarshalFrom, MarshalWith, StringMarshaller } from 'raynor'

import { Env } from '@truesparrow/common-js'
import { WebFetcher } from '@truesparrow/common-server-js'

import { Auth0Config } from '../auth0'
import { PathMatch, PostLoginRedirectInfo, PostLoginRedirectInfoMarshaller } from '../auth-flow'
import { IdentityClient } from '../client'
import { RequestWithIdentity } from '../request'
import {
    newSessionMiddleware,
    SessionLevel,
    SessionInfoSource,
    setSessionTokenOnResponse,
    clearSessionTokenOnResponse
} from './session-middleware'
import { SessionToken } from '../session-token'


export class Auth0AccessTokenMarshaller extends StringMarshaller {
    private static readonly _alnumRegExp: RegExp = new RegExp('^[0-9a-zA-Z_-]+$');

    filter(s: string): string {
        if (s.length == 0) {
            throw new ExtractError('Expected a string to be non-empty');
        }

        if (!Auth0AccessTokenMarshaller._alnumRegExp.test(s)) {
            throw new ExtractError('Should only contain alphanumerics');
        }

        return s;
    }
}


export class Auth0AuthorizationCodeMarshaller extends StringMarshaller {
    private static readonly _alnumRegExp: RegExp = new RegExp('^[0-9a-zA-Z_-]+$');

    filter(s: string): string {
        if (s.length == 0) {
            throw new ExtractError('Expected a string to be non-empty');
        }

        if (!Auth0AuthorizationCodeMarshaller._alnumRegExp.test(s)) {
            throw new ExtractError('Should only contain alphanumerics');
        }

        return s;
    }
}


export class Auth0AuthorizeRedirectInfo {
    @MarshalWith(Auth0AuthorizationCodeMarshaller, 'code')
    authorizationCode: string;

    @MarshalWith(r.StringMarshaller)
    state: PostLoginRedirectInfo;

    constructor(authorizationCode: string, state: PostLoginRedirectInfo) {
        this.authorizationCode = authorizationCode;
        this.state = state;
    }
}


export function Auth0AuthorizeRedirectInfoMarshaller(allowedPaths: PathMatch[]): r.MarshallerConstructor<Auth0AuthorizeRedirectInfo> {
    return class extends MarshalFrom(Auth0AuthorizeRedirectInfo) {
        private readonly _postLoginRedirectInfoMarshaller = new (PostLoginRedirectInfoMarshaller(allowedPaths))();

        filter(auth0AuthorizeRedirectInfo: Auth0AuthorizeRedirectInfo): Auth0AuthorizeRedirectInfo {
            return new Auth0AuthorizeRedirectInfo(
                auth0AuthorizeRedirectInfo.authorizationCode,
                this._postLoginRedirectInfoMarshaller.extract(auth0AuthorizeRedirectInfo.state)
            );
        }

        unbuild(auth0AutorizeRedirectInfo: Auth0AuthorizeRedirectInfo): object {
            // Ugly stuff needs to happen here because Raynor isn't there yet.
            return super.unbuild({
                authorizationCode: auth0AutorizeRedirectInfo.authorizationCode,
                state: this._postLoginRedirectInfoMarshaller.pack(auth0AutorizeRedirectInfo.state)
            });
        }
    };
}


class Auth0TokenExchangeResult {
    @MarshalWith(Auth0AccessTokenMarshaller, 'access_token')
    accessToken: string;
}


const AUTHORIZE_OPTIONS = {
    method: 'POST',
    mode: 'cors',
    cache: 'no-cache',
    redirect: 'error',
    referrer: 'client',
    headers: {
        'Content-Type': 'application/json'
    }
};


/**
 * Create a new router which takes care of the auth flow with [Auth0]{@link https://auth0.com} as
 * an identity provider manager. This router is meant to be installed on a backend for frontend
 * type service, as it is technically part of the "frontend". It won't display any page or anything,
 * but just make changes to the identity service and redirect according to the configuration setup
 * here. This is just the way authentication flows work on the web.
 *
 * @note The router has two paths exposed: /login and /logout. These are invoked by Auth0, via
 *     redirection with specific parameters containing information about the signed in user.
 * @note The router assumes the common middleware is used.
 * @param env - the environment in which the code is running.
 * @param allowedPaths - a set of allowed path prefixes.
 * @param auth0Config - the configuration for Auth0.
 * @param webFetcher - a fetcher object.
 * @param identityClient - a client for the identity service.
 * @return An express router instance which implement the auth flow for the identity service via
 *     Auth0.
 */
export function newAuth0AuthFlowRouter(
    env: Env,
    allowedPaths: PathMatch[],
    auth0Config: Auth0Config,
    webFetcher: WebFetcher,
    identityClient: IdentityClient): express.Router {
    const auth0TokenExchangeResultMarshaller = new (MarshalFrom(Auth0TokenExchangeResult))();
    const auth0AuthorizeRedirectInfoMarshaller = new (Auth0AuthorizeRedirectInfoMarshaller(allowedPaths))();

    const router = express.Router();

    router.post('/login', [newSessionMiddleware(SessionLevel.Session, SessionInfoSource.Cookie, env, identityClient)], wrap(async (req: RequestWithIdentity, res: express.Response) => {
        let redirectInfo: Auth0AuthorizeRedirectInfo | null = null;
        try {
            redirectInfo = auth0AuthorizeRedirectInfoMarshaller.extract(req.query);
        } catch (e) {
            req.log.error('Auth error');
            req.errorLog.error(e);
            res.status(HttpStatus.BAD_REQUEST);
            res.end();
            return;
        }

        const options = (Object as any).assign({}, AUTHORIZE_OPTIONS, {
            body: JSON.stringify({
                grant_type: 'authorization_code',
                client_id: auth0Config.clientId,
                client_secret: auth0Config.clientSecret,
                code: redirectInfo.authorizationCode,
                redirect_uri: auth0Config.loginCallbackUri
            })
        });

        let rawResponse: Response;
        try {
            rawResponse = await webFetcher.fetch(`https://${auth0Config.domain}/oauth/token`, options);
        } catch (e) {
            req.log.error(e);
            req.errorLog.error(e);
            res.status(HttpStatus.BAD_GATEWAY);
            res.end();
            return;
        }

        let auth0TokenExchangeResult: Auth0TokenExchangeResult | null = null;
        if (rawResponse.ok) {
            try {
                const jsonResponse = await rawResponse.json();
                auth0TokenExchangeResult = auth0TokenExchangeResultMarshaller.extract(jsonResponse);
            } catch (e) {
                req.log.error(e, 'Deserialization error');
                req.errorLog.error(e);
                res.status(HttpStatus.INTERNAL_SERVER_ERROR);
                res.end();
                return;
            }
        } else {
            req.log.error(`Auth error - bad code ${rawResponse.status}`);
            req.errorLog.error(`Auth error - bad code ${rawResponse.status}`);
            res.status(HttpStatus.BAD_GATEWAY);
            res.end();
            return;
        }

        let sessionToken = new SessionToken((req.sessionToken).sessionId, auth0TokenExchangeResult.accessToken);

        try {
            sessionToken = (await identityClient.withContext(sessionToken).getOrCreateUserOnSession(req.session))[0];
        } catch (e) {
            if (e.name == 'UnauthorizedIdentityError') {
                req.log.error(e);
                res.status(HttpStatus.UNAUTHORIZED);
                res.end();
                return;
            }

            if (e.name == 'IdentityError') {
                req.log.error(e);
                res.status(HttpStatus.BAD_GATEWAY);
                res.end();
                return;
            }

            req.log.error(e);
            req.errorLog.error(e);
            res.status(HttpStatus.INTERNAL_SERVER_ERROR);
            res.end();
            return;
        }

        setSessionTokenOnResponse(res, req.requestTime, sessionToken, SessionInfoSource.Cookie, env);
        res.redirect(redirectInfo.state.path);
    }));

    router.post('/logout', [newSessionMiddleware(SessionLevel.SessionAndUser, SessionInfoSource.Cookie, env, identityClient)], wrap(async (req: RequestWithIdentity, res: express.Response) => {
        try {
            await identityClient.withContext(req.sessionToken as SessionToken).removeSession(req.session);
        } catch (e) {
            if (e.name == 'UnauthorizedIdentityError') {
                req.log.error(e);
                res.status(HttpStatus.UNAUTHORIZED);
                res.end();
                return;
            }

            if (e.name == 'IdentityError') {
                req.log.error(e);
                res.status(HttpStatus.BAD_GATEWAY);
                res.end();
                return;
            }

            req.log.error(e);
            req.errorLog.error(e);
            res.status(HttpStatus.INTERNAL_SERVER_ERROR);
            res.end();
            return;
        }

        clearSessionTokenOnResponse(res, SessionInfoSource.Cookie, env);
        res.redirect('/');
    }));

    return router;
}
