/** Defines the session middleware and some utilities for it. */

/** Imports. Also so typedoc works correctly. */
import * as cookieParser from 'cookie-parser'
import * as express from 'express'
import * as HttpStatus from 'http-status-codes'
import * as moment from 'moment'
import { MarshalFrom } from 'raynor'

import { Env, isLocal } from '@truesparrow/common-js'

import { SessionToken } from '../session-token'
import { IdentityClient, SESSION_TOKEN_COOKIE_NAME, SESSION_TOKEN_HEADER_NAME } from '../client'
import { RequestWithIdentity } from '../request'


/**
 * The requirements for the session a request belongs to.
 */
export enum SessionLevel {
    /** It isn't necessary for a session to exist. If it exists, we use it, but if it doesn't we create a new one. */
    None,
    /** A session must exist and it's going to be attached to the request. */
    Session,
    /** A session for a user account must exist and it's going to be attached to the request. */
    SessionAndUser
}

/**
 * Where to find the session information.
 */
export enum SessionInfoSource {
    /** Can be found as a cookie. Usually used for frontend services. */
    Cookie,
    /** Can be found as a special header. Usually used for API services. */
    Header
}


/**
 * Create a connect middleware which populates the incoming request's {@link RequestWithIdentity.session} property
 * with a {@link Session} object. It does this by looking at either cookies or headers in the HTTP request, extracting
 * authentication information and using this to retrieve data about the session and potentially user from the identity
 * service. It also re-attaches the auth info to the response, as either a cookie or a header.
 * @param sessionLevel - how much of a session to expect to exist.
 * @param sessionInfoSource - where to extract the session from the request, and where to place the session info on
 *     the response.
 * @param env - the environment the code is running in.
 * @param identityClient - an {@link IdentityClient} for communicating with the identity service.
 * @returns A connect middleware of type {@link express.RequestHandler}.
 */
export function newSessionMiddleware(
    sessionLevel: SessionLevel,
    sessionInfoSource: SessionInfoSource,
    env: Env,
    identityClient: IdentityClient): express.RequestHandler {
    const sessionTokenMarshaller = new (MarshalFrom(SessionToken))();
    const cookieParserMiddleware = cookieParser();

    let mustHaveSession = false;
    let mustHaveUser = false;

    // A nice use of switch fall through.
    switch (sessionLevel) {
        case SessionLevel.SessionAndUser:
            mustHaveUser = true;
        case SessionLevel.Session:
            mustHaveSession = true;
    }

    return (req: RequestWithIdentity, res: express.Response, next: express.NextFunction) => {
        cookieParserMiddleware(req, res, () => {
            let sessionTokenSerialized: string | null = null;

            // Try to retrieve any side-channel auth information in the request. This can appear
            // either as a cookie with the name SESSION_TOKEN_COOKIE_NAME, or as a header with the name
            // SESSION_TOKEN_HEADER_NAME.
            if (sessionInfoSource == SessionInfoSource.Cookie && req.cookies[SESSION_TOKEN_COOKIE_NAME] != undefined) {
                sessionTokenSerialized = req.cookies[SESSION_TOKEN_COOKIE_NAME];
            } else if (sessionInfoSource == SessionInfoSource.Header && req.header(SESSION_TOKEN_HEADER_NAME) != undefined) {
                try {
                    sessionTokenSerialized = JSON.parse(req.header(SESSION_TOKEN_HEADER_NAME) as string);
                } catch (e) {
                    req.log.error(e);
                    res.status(HttpStatus.BAD_REQUEST);
                    res.end();
                    return;
                }
            }

            // Treat the case of no auth info. If it's required the request handling is stopped with an
            // error, otherwise future handlers are invoked.
            if (sessionTokenSerialized == null) {
                if (mustHaveSession) {
                    req.log.warn('Expected some auth info but there was none');
                    res.status(HttpStatus.BAD_REQUEST);
                    res.end();
                    return;
                }

                identityClient
                    .getOrCreateSession()
                    .then(([sessionToken, session]) => {
                        req.sessionToken = sessionToken;
                        req.session = session;
                        setSessionTokenOnResponse(res, req.requestTime, sessionToken, sessionInfoSource, env);
                        next();
                    })
                    .catch(e => {
                        if (e.name == 'IdentityError') {
                            req.log.error(e);
                            res.status(HttpStatus.BAD_GATEWAY);
                            res.end();
                            return;
                        }

                        req.log.error(e);
                        res.status(HttpStatus.INTERNAL_SERVER_ERROR);
                        res.end();
                    });
                return;
            }

            // If there is some auth info, let's extract it.
            let sessionToken: SessionToken | null = null;
            try {
                sessionToken = sessionTokenMarshaller.extract(sessionTokenSerialized);
            } catch (e) {
                req.log.error(e);
                res.status(HttpStatus.BAD_REQUEST);
                res.end();
                return;
            }

            // Treat the case of incomplete auth info. If we're supposed to also have a user, but there
            // is none, the request handling is stopped with an error.
            if (mustHaveUser && sessionToken.userToken == null) {
                req.log.warn('Expected auth token but none was had');
                res.status(HttpStatus.BAD_REQUEST);
                res.end();
                return;
            }

            // Actually retrieve the session info and attach it to the request.
            if (sessionToken.userToken == null) {
                identityClient
                    .withContext(sessionToken as SessionToken)
                    .getSession()
                    .then(session => {
                        req.sessionToken = sessionToken as SessionToken;
                        req.session = session;
                        setSessionTokenOnResponse(res, req.requestTime, sessionToken as SessionToken, sessionInfoSource, env);
                        next();
                    })
                    .catch(e => {
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
                        res.status(HttpStatus.INTERNAL_SERVER_ERROR);
                        res.end();
                        return;
                    });
            } else {
                identityClient
                    .withContext(sessionToken as SessionToken)
                    .getUserOnSession()
                    .then((session) => {
                        req.sessionToken = sessionToken as SessionToken;
                        req.session = session;
                        setSessionTokenOnResponse(res, req.requestTime, sessionToken as SessionToken, sessionInfoSource, env);
                        next();
                    })
                    .catch(e => {
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
                        res.status(HttpStatus.INTERNAL_SERVER_ERROR);
                        res.end();
                        return;
                    });
            }
        });
    };
}


/**
 * Attach the given {@link SessionToken} to the request. Depending on {@link sessionInfoSource},
 * this means either setting a cookie to the serialized content of the token, or setting a header
 * to the same value. The cookie is http only, secure in production, does not expire and has the
 * sameSite attribute to protect against XSS attacks.
 * @param res - the response to attach the info to.
 * @param rightNow - the request's time
 * @param sessionToken - the token to attach to the request.
 * @param sessionInfoSource - where to place the session info on.
 * @param env - the environment this code is running in.
 */
export function setSessionTokenOnResponse(
    res: express.Response,
    rightNow: Date,
    sessionToken: SessionToken,
    sessionInfoSource: SessionInfoSource,
    env: Env): void {
    const sessionTokenMarshaller = new (MarshalFrom(SessionToken))();

    switch (sessionInfoSource) {
        case SessionInfoSource.Cookie:
            res.cookie(SESSION_TOKEN_COOKIE_NAME, sessionTokenMarshaller.pack(sessionToken), {
                httpOnly: true,
                secure: !isLocal(env),
                expires: moment.utc(rightNow).add(10000, 'days').toDate(),
                sameSite: 'lax'
            });
            break;
        case SessionInfoSource.Header:
            res.setHeader(SESSION_TOKEN_HEADER_NAME, JSON.stringify(sessionTokenMarshaller.pack(sessionToken)));
            break;
    }
}


/**
 * Remove the any {@link SessionToken} from the request. Depending on {@link sessionInfoSource},
 * this means either clearing the cookie or the header from the response object.
 * @param res - the response to clear the info from.
 * @param sessionInfoSource - where to clear the session info from.
 * @param env - the environment this code is running in.
 */
export function clearSessionTokenOnResponse(res: express.Response, sessionInfoSource: SessionInfoSource, env: Env) {
    switch (sessionInfoSource) {
        case SessionInfoSource.Cookie:
            res.clearCookie(SESSION_TOKEN_COOKIE_NAME, { httpOnly: true, secure: !isLocal(env), sameSite: 'lax' });
            break;
        case SessionInfoSource.Header:
            res.removeHeader(SESSION_TOKEN_HEADER_NAME);
            break;
    }
}
