/** Utilities for the UI parts of Auth0. */

/** Imports. Also so typedoc works correctly. */
import { Marshaller } from 'raynor'
import 'require-ensure'

import { PathMatch, PostLoginRedirectInfo, PostLoginRedirectInfoMarshaller } from '../auth-flow'
import { Auth0ClientConfig } from '../auth0'


/**
 * A UI component which shows the login/signup screen via Auth0. The heavy lifting is done
 * by Auth0, and this just does things our way.
 */
export class Auth0Lock {
    private readonly _postLoginRedirectInfoMarshaller: Marshaller<PostLoginRedirectInfo>;
    private readonly _auth0ClientConfig: Auth0ClientConfig;

    /**
     * Construct a {@link Auth0Lock}.
     * @param allowedPaths - a list of path prefixes which are permitted.
     * @param auth0ClientConfig - the client configuration for Auth0.
     */
    constructor(allowedPaths: PathMatch[], auth0ClientConfig: Auth0ClientConfig) {
        this._postLoginRedirectInfoMarshaller = new (PostLoginRedirectInfoMarshaller(allowedPaths))();
        this._auth0ClientConfig = auth0ClientConfig;
    }

    /**
     * Show the UI component which shows the login/signup screen via Auth0. This allows a user to
     * login or signup, and triggers the authentication flow to start.
     * @details This will load another chunk containing mostly the
     * [Auth0 Lock]{@link https://auth0.com/lock} library and dependencies. The reason this is so
     * is that the library itself is _very_ big, but it is only useful rarely (when somebody logs in
     * or tries to signup).
     * @param redirectLocation - the location the lock will redirect to after a successful login.
     * @param canDismiss - whether the UI component can be dismissed or not.
     */
    showLock(redirectLocation: Location, canDismiss: boolean = true): void {
        var _this = this;

        // This generates an async chunk.
        (require as any).ensure([], function(asyncRequire: (moduleName: string) => any) {
            const auth0Lock = asyncRequire('auth0-lock');

            const postLoginInfo = new PostLoginRedirectInfo(redirectLocation.pathname);
            const postLoginInfoSer = _this._postLoginRedirectInfoMarshaller.pack(postLoginInfo);

            const auth0: any = new ((auth0Lock as any).default)(
                _this._auth0ClientConfig.clientId,
                _this._auth0ClientConfig.domain, {
                    closable: canDismiss,
                    auth: {
                        redirect: true,
                        redirectUrl: _this._auth0ClientConfig.loginCallbackUri,
                        responseType: 'code',
                        params: {
                            state: postLoginInfoSer
                        }
                    }
                }
            );

            auth0.show();
        }, 'auth0-lock');
    }
}
