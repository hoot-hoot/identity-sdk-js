/** Defines a client for the identity service. */

/** Imports. Also so typedoc works correctly. */
import * as HttpStatus from 'http-status-codes'
import { Marshaller, MarshalFrom } from 'raynor'

import { Env, isLocal } from '@hoot-hoot/common-js'
import { WebFetcher } from '@hoot-hoot/common-server-js'

import { SessionToken } from './session-token'
import { PublicUser, Session } from './entities'
import {
    SessionAndTokenResponse,
    SessionResponse,
    UsersInfoResponse
} from './dtos'


/** The name of the cookie which contains the session token for browser->server communication. */
export const SESSION_TOKEN_COOKIE_NAME: string = 'hoot-hoot-sessiontoken';
/** The name of the header which contains the session token for server->server communication. */
export const SESSION_TOKEN_HEADER_NAME: string = 'X-Hoot-Hoot-SessionToken';
/** The name of the header which contains the XSRF token. */
export const XSRF_TOKEN_HEADER_NAME: string = 'X-Hoot-Hoot-XsrfToken';


/** The base error raised by methods of the {@link IdentityClient}. */
export class IdentityError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'IdentityError';
    }
}


/** An error raised when somebody tries do to something and they're not authorized to do so. */
export class UnauthorizedIdentityError extends IdentityError {
    constructor(message: string) {
        super(message);
        this.name = 'UnauthorizedIdentityError';
    }
}


/**
 * An interface for communicating with the identity service directly. Mostly, you're expected
 * to use the various middleware, but sometimes you need to speak with it directly (like when
 * agreeing to a cookie) and this is the way to do it.
 *
 * Notice that in some context (such as the browser), the existence of a {@link SessionToken}
 * is implied and every operation is done relative to that session. In others, you need to
 * explicitly associate a token via {@link IdentityClient.withContext}.
 */
export interface IdentityClient {
    /**
     * Attach a given {@link SessionToken} to the client and return a new one which is restricted
     * to just the session identified by the token.
     * @param sessionToken - the session token to build a client for.
     * @return a new client, restricted to just the session identified by the token.
     */
    withContext(sessionToken: SessionToken): IdentityClient;

    /**
     * Retrieve a the session associated with the current token, or create a new one if there's no token.
     * @return A pair of associated {@link SessionToken} and {@link Session}.
     * @throws If there's a communication error throws an {@link IdentityError}.
     */
    getOrCreateSession(): Promise<[SessionToken, Session]>;

    /**
     * Retrieve a session associated with the current token.
     * @return The session associated with the current token.
     * @throws If there's a communication error throws an {@link IdentityError}. If the operation
     * isn't authorized (such as the token not having a session), throw a {@link UnauthorizedIdentityError}.
     */
    getSession(): Promise<Session>;

    /**
     * Remove the session associated with the current token.
     * @param session - needed for the XSRF token.
     * @throws If there's a communication error throws an {@link IdentityError}.
     */
    removeSession(session: Session): Promise<void>;

    /**
     * Agree to the cookie policy for this session/user.
     * @param session - needed for the XSRF token.
     * @return the new form of the {@link Session}.
     * @throws If there's a communication error throws an {@link IdentityError}. If the operation
     * isn't authorized (such as the token not having a session), throw a {@link UnauthorizedIdentityError}.
     */
    agreeToCookiePolicyForSession(session: Session): Promise<Session>;

    /**
     * Retrieve the session with a user associated with the current token, or create one if there's no
     * user. The session must exist, and the token must contain the {@link SessionToken.userToken}.
     * @param session - needed for the XSRF token.
     * @return A pair of associated {@link SessionToken} and {@link Session}.
     * @throws If there's a communication error throws an {@link IdentityError}. If the operation
     * isn't authorized (such as the token not having a session), throw a {@link UnauthorizedIdentityError}.
     */
    getOrCreateUserOnSession(session: Session): Promise<[SessionToken, Session]>;

    /**
     * Retrieve a session associated with the current token, including the user.
     * @return The session associated with the current token, with the user.
     * @throws If there's a communication error throws an {@link IdentityError}. If the operation
     * isn't authorized (such as the token not having a session), throw a {@link UnauthorizedIdentityError}.
     */
    getUserOnSession(): Promise<Session>;

    /**
     * Return information about all users.
     * @return A list of {@link PublicUser} information.
     * @throws If there's a communication error throws an {@link IdentityError}.
     */
    getUsersInfo(ids: number[]): Promise<PublicUser[]>;
}


/**
 * Create an {@link IdentityClient}.
 * @param env - the {@link Env} the client is running in.
 * @param origin - the [origin]{@link https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Origin}
 *     to use for the requests originating from the client. Doesn't "change" things for browser work.
 * @param identityServiceHost - the hostname for the identity service servers.
 * @param webFetcher - a {@link WebFetcher} to use to make requests.
 * @return a new {@link IdentityClient}. On server there's no context, whereas on the browser it's implied.
 */
export function newIdentityClient(env: Env, origin: string, identityServiceHost: string, webFetcher: WebFetcher): IdentityClient {
    const sessionTokenMarshaller = new (MarshalFrom(SessionToken))();
    const sessionAndTokenResponseMarshaller = new (MarshalFrom(SessionAndTokenResponse))();
    const sessionResponseMarshaller = new (MarshalFrom(SessionResponse))();
    const usersInfoResponseMarshaller = new (MarshalFrom(UsersInfoResponse))();

    return new IdentityClientImpl(
        env,
        origin,
        identityServiceHost,
        webFetcher,
        sessionTokenMarshaller,
        sessionAndTokenResponseMarshaller,
        sessionResponseMarshaller,
        usersInfoResponseMarshaller);
}


class IdentityClientImpl implements IdentityClient {
    private static readonly _getOrCreateSessionOptions: RequestInit = {
        method: 'POST',
        cache: 'no-cache',
        redirect: 'error',
        referrer: 'client',
    };

    private static readonly _getSessionOptions: RequestInit = {
        method: 'GET',
        cache: 'no-cache',
        redirect: 'error',
        referrer: 'client',
    };

    private static readonly _expireSessionOptions: RequestInit = {
        method: 'DELETE',
        cache: 'no-cache',
        redirect: 'error',
        referrer: 'client',
    };

    private static readonly _agreeToCookiePolicyForSessionOptions: RequestInit = {
        method: 'POST',
        cache: 'no-cache',
        redirect: 'error',
        referrer: 'client',
    };

    private static readonly _getOrCreateUserOnSessionOptions: RequestInit = {
        method: 'POST',
        cache: 'no-cache',
        redirect: 'error',
        referrer: 'client',
    };

    private static readonly _getUserOnSessionOptions: RequestInit = {
        method: 'GET',
        cache: 'no-cache',
        redirect: 'error',
        referrer: 'client',
    };

    private static readonly _getUsersInfoOptions: RequestInit = {
        method: 'GET',
        cache: 'no-cache',
        redirect: 'error',
        referrer: 'client',
    };

    private readonly _env: Env;
    private readonly _origin: string;
    private readonly _identityServiceHost: string;
    private readonly _webFetcher: WebFetcher;
    private readonly _sessionTokenMarshaller: Marshaller<SessionToken>;
    private readonly _sessionAndTokenResponseMarshaller: Marshaller<SessionAndTokenResponse>;
    private readonly _sessionResponseMarshaller: Marshaller<SessionResponse>;
    private readonly _usersInfoResponseMarshaller: Marshaller<UsersInfoResponse>;
    private readonly _defaultHeaders: HeadersInit;
    private readonly _protocol: string;

    constructor(
        env: Env,
        origin: string,
        identityServiceHost: string,
        webFetcher: WebFetcher,
        sessionTokenMarshaller: Marshaller<SessionToken>,
        sessionAndTokenResponseMarshaler: Marshaller<SessionAndTokenResponse>,
        sessionResponseMarshaller: Marshaller<SessionResponse>,
        usersInfoResponseMarshaller: Marshaller<UsersInfoResponse>,
        sessionToken: SessionToken | null = null) {
        this._env = env;
        this._origin = origin;
        this._identityServiceHost = identityServiceHost;
        this._webFetcher = webFetcher;
        this._sessionTokenMarshaller = sessionTokenMarshaller;
        this._sessionAndTokenResponseMarshaller = sessionAndTokenResponseMarshaler
        this._sessionResponseMarshaller = sessionResponseMarshaller;
        this._usersInfoResponseMarshaller = usersInfoResponseMarshaller;

        this._defaultHeaders = {
            'Origin': origin
        }

        if (sessionToken != null) {
            this._defaultHeaders[SESSION_TOKEN_HEADER_NAME] = JSON.stringify(this._sessionTokenMarshaller.pack(sessionToken));
        }

        if (isLocal(this._env)) {
            this._protocol = 'http';
        } else {
            this._protocol = 'https';
        }
    }

    withContext(sessionToken: SessionToken): IdentityClient {
        return new IdentityClientImpl(
            this._env,
            this._origin,
            this._identityServiceHost,
            this._webFetcher,
            this._sessionTokenMarshaller,
            this._sessionAndTokenResponseMarshaller,
            this._sessionResponseMarshaller,
            this._usersInfoResponseMarshaller,
            sessionToken);
    }

    async getOrCreateSession(): Promise<[SessionToken, Session]> {
        const options = this._buildOptions(IdentityClientImpl._getOrCreateSessionOptions);

        let rawResponse: Response;
        try {
            rawResponse = await this._webFetcher.fetch(`${this._protocol}://${this._identityServiceHost}/session`, options);
        } catch (e) {
            throw new IdentityError(`Request failed because '${e.toString()}'`);
        }

        if (rawResponse.ok) {
            try {
                const jsonResponse = await rawResponse.json();
                const sessionResponse = this._sessionAndTokenResponseMarshaller.extract(jsonResponse);
                return [sessionResponse.sessionToken, sessionResponse.session];
            } catch (e) {
                throw new IdentityError(`JSON decoding error because '${e.toString()}'`);
            }
        } else {
            throw new IdentityError(`Service response ${rawResponse.status}`);
        }
    }

    async getSession(): Promise<Session> {
        const options = this._buildOptions(IdentityClientImpl._getSessionOptions);

        let rawResponse: Response;
        try {
            rawResponse = await this._webFetcher.fetch(`${this._protocol}://${this._identityServiceHost}/session`, options);
        } catch (e) {
            throw new IdentityError(`Request failed because '${e.toString()}'`);
        }

        if (rawResponse.ok) {
            try {
                const jsonResponse = await rawResponse.json();
                const sessionResponse = this._sessionResponseMarshaller.extract(jsonResponse);
                return sessionResponse.session;
            } catch (e) {
                throw new IdentityError(`JSON decoding error because '${e.toString()}'`);
            }
        } else if (rawResponse.status == HttpStatus.UNAUTHORIZED) {
            throw new UnauthorizedIdentityError('User is not authorized');
        } else {
            throw new IdentityError(`Service response ${rawResponse.status}`);
        }
    }

    async removeSession(session: Session): Promise<void> {
        const options = this._buildOptions(IdentityClientImpl._expireSessionOptions, session);

        let rawResponse: Response;
        try {
            rawResponse = await this._webFetcher.fetch(`${this._protocol}://${this._identityServiceHost}/session`, options);
        } catch (e) {
            throw new IdentityError(`Request failed because '${e.toString()}'`);
        }

        if (rawResponse.ok) {
            // Do nothing
        } else if (rawResponse.status == HttpStatus.UNAUTHORIZED) {
            throw new UnauthorizedIdentityError('User is not authorized');
        } else {
            throw new IdentityError(`Service response ${rawResponse.status}`);
        }
    }

    async agreeToCookiePolicyForSession(session: Session): Promise<Session> {
        const options = this._buildOptions(IdentityClientImpl._agreeToCookiePolicyForSessionOptions, session);

        let rawResponse: Response;
        try {
            rawResponse = await this._webFetcher.fetch(`${this._protocol}://${this._identityServiceHost}/session/agree-to-cookie-policy`, options);
        } catch (e) {
            throw new IdentityError(`Request failed because '${e.toString()}'`);
        }

        if (rawResponse.ok) {
            try {
                const jsonResponse = await rawResponse.json();
                const sessionResponse = this._sessionResponseMarshaller.extract(jsonResponse);
                return sessionResponse.session;
            } catch (e) {
                throw new IdentityError(`JSON decoding error because '${e.toString()}'`);
            }
        } else if (rawResponse.status == HttpStatus.UNAUTHORIZED) {
            throw new UnauthorizedIdentityError('User is not authorized');
        } else {
            throw new IdentityError(`Service response ${rawResponse.status}`);
        }
    }

    async getOrCreateUserOnSession(session: Session): Promise<[SessionToken, Session]> {
        const options = this._buildOptions(IdentityClientImpl._getOrCreateUserOnSessionOptions, session);

        let rawResponse: Response;
        try {
            rawResponse = await this._webFetcher.fetch(`${this._protocol}://${this._identityServiceHost}/user`, options);
        } catch (e) {
            throw new IdentityError(`Request failed because '${e.toString()}'`);
        }

        if (rawResponse.ok) {
            try {
                const jsonResponse = await rawResponse.json();
                const sessionResponse = this._sessionAndTokenResponseMarshaller.extract(jsonResponse);
                return [sessionResponse.sessionToken, sessionResponse.session];
            } catch (e) {
                throw new IdentityError(`JSON decoding error because '${e.toString()}'`);
            }
        } else if (rawResponse.status == HttpStatus.UNAUTHORIZED) {
            throw new UnauthorizedIdentityError('User is not authorized');
        } else {
            throw new IdentityError(`Service response ${rawResponse.status}`);
        }
    }

    async getUserOnSession(): Promise<Session> {
        const options = this._buildOptions(IdentityClientImpl._getUserOnSessionOptions);

        let rawResponse: Response;
        try {
            rawResponse = await this._webFetcher.fetch(`${this._protocol}://${this._identityServiceHost}/user`, options);
        } catch (e) {
            throw new IdentityError(`Request failed because '${e.toString()}'`);
        }

        if (rawResponse.ok) {
            try {
                const jsonResponse = await rawResponse.json();
                const sessionResponse = this._sessionResponseMarshaller.extract(jsonResponse);
                return sessionResponse.session;
            } catch (e) {
                throw new IdentityError(`JSON decoding error because '${e.toString()}'`);
            }
        } else if (rawResponse.status == HttpStatus.UNAUTHORIZED) {
            throw new UnauthorizedIdentityError('User is not authorized');
        } else {
            throw new IdentityError(`Service response ${rawResponse.status}`);
        }
    }

    async getUsersInfo(ids: number[]): Promise<PublicUser[]> {
        const dedupedIds: number[] = [];
        for (let id of ids) {
            if (dedupedIds.indexOf(id) != -1)
                continue;
            dedupedIds.push(id);
        }

        const options = this._buildOptions(IdentityClientImpl._getUsersInfoOptions);

        let rawResponse: Response;
        try {
            const encodedIds = encodeURIComponent(JSON.stringify(dedupedIds));
            rawResponse = await this._webFetcher.fetch(`${this._protocol}://${this._identityServiceHost}/users-info?ids=${encodedIds}`, options);
        } catch (e) {
            throw new IdentityError(`Request failed because '${e.toString()}'`);
        }

        if (rawResponse.ok) {
            try {
                const jsonResponse = await rawResponse.json();
                const usersInfoResponse = this._usersInfoResponseMarshaller.extract(jsonResponse);
                return usersInfoResponse.usersInfo;
            } catch (e) {
                throw new IdentityError(`JSON decoding error because '${e.toString()}'`);
            }
        } else {
            throw new IdentityError(`Service response ${rawResponse.status}`);
        }
    }

    private _buildOptions(template: RequestInit, session: Session | null = null) {
        const options = (Object as any).assign({ headers: this._defaultHeaders }, template);

        if (session != null) {
            options.headers = (Object as any).assign(options.headers, { [XSRF_TOKEN_HEADER_NAME]: session.xsrfToken });
        }

        return options;
    }
}
