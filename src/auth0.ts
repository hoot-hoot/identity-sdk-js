/** Mostly the configuration for anything Auth0 related. */

/** The [Auth0]{@link https://auth0.com} configuration. Should be secret. */
export class Auth0Config {
    /** The client id provided to us by Auth0. */
    clientId: string;
    /** The "secret" provided to us by Auth0. Should not be public. */
    clientSecret: string;
    /** Our domain with Auth0. Different for each "client" we have. We have one client per environment. */
    domain: string;
    /** The uri to invoke in the auth flow for logins. */
    loginCallbackUri: string;
}
