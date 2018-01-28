/** Mostly the configuration for anything Auth0 related. */


/** The [Auth0]{@link http://auth0.com} configuration for _client_ code. This can be made public. */
export class Auth0ClientConfig {
    /** The client id provided to us by Auth0. */
    clientId: string;
    /** Our domain with Auth0. Different for each "client" we have. */
    domain: string;
    /** The uri to invoke in the auth flow for logins. */
    loginCallbackUri: string;
}

/** The [Auth0]{@link https://auth0.com} configuration for _server_ code. Should be secret. */
export class Auth0ServerConfig {
    /** The client id provided to us by Auth0. */
    clientId: string;
    /** The "secret" provided to us by Auth0. Should not be public. */
    clientSecret: string;
    /** Our domain with Auth0. Different for each "client" we have. We have one client per environment. */
    domain: string;
    /** The uri to invoke in the auth flow for logins. */
    loginCallbackUri: string;
}


/**
 * Produce a client version of this config, with the secret server-side data stripped out.
 * @param auth0ServerConfig - the server config to transform.
 * @return The client version of the config.
 */
export function serverToClient(auth0ServerConfig: Auth0ServerConfig): Auth0ClientConfig {
    return {
        clientId: auth0ServerConfig.clientId,
        domain: auth0ServerConfig.domain,
        loginCallbackUri: auth0ServerConfig.loginCallbackUri
    };
}
