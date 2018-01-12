/** Common types relevant to the auth flow. */

/** Imports. Also so typedoc works correctly. */
import * as r from 'raynor'
import { ExtractError, MarshalFrom, MarshalWith } from 'raynor'
import * as serializeJavascript from 'serialize-javascript'


/**
 * Information passed to the identity provider as part of the login flow, which it returns to us,
 * as a means of maintaining state across the various requests and redirects.
 */
export class PostLoginRedirectInfo {
    /**
     * The path of the view the user was on when the auth flow began. Used so the application knows
     * where to return to.
     */
    @MarshalWith(r.PathAndQueryAndFragmentMarshaller)
    path: string;

    /**
     * Construct a {@link PostLoginRedirectInfo}.
     * @param path - The path of the view the user was on when the auth flow began.
     */
    constructor(path: string) {
        this.path = path;
    }
}


/**
 * The way we're supposed to look at an allowed path. Either match the prefix
 * or the full path.
 */
export type PathMatch = {
    path: string,
    mode: 'prefix'|'full'
};


/**
 * A marshaller for {@link PostLoginRedirectInfo}. This is a bit more involved than a regular
 * marshaller obtained via {@link MarshalFrom}, since the basic representation is that of a string.
 * For deep lore reasons the basic representation is doubly URI encoded.
 * @note This is a function returning a class. So you can use it both in new expressions as well
 * as in `@MarshalWith` annotations.
 * @param allowedPaths - the set of allowed path prefixes.
 */
export function PostLoginRedirectInfoMarshaller(allowedPaths: PathMatch[]): r.MarshallerConstructor<PostLoginRedirectInfo> {
    const localAllowedPaths = allowedPaths.slice(0);

    return class extends r.BaseStringMarshaller<PostLoginRedirectInfo> {
        private readonly _objectMarshaller = new (MarshalFrom(PostLoginRedirectInfo))();

        build(a: string): PostLoginRedirectInfo {
            let path: string|null;
            try {
                // Don't ask. Auth0 seems to double encode this.
                const redirectInfoSer = decodeURIComponent(decodeURIComponent(a));
                const redirectInfoRaw = JSON.parse(redirectInfoSer);
                const redirectInfo = this._objectMarshaller.extract(redirectInfoRaw);
                path = redirectInfo.path;
                for (let allowedPath of localAllowedPaths) {
                    switch (allowedPath.mode) {
                    case 'prefix':
                        if (redirectInfo.path.indexOf(allowedPath.path) == 0) {
                            return redirectInfo;
                        }
                        break;
                    case 'full':
                        if (redirectInfo.path == allowedPath.path) {
                            return redirectInfo;
                        }
                        break;
                    }
                }
            } catch (e) {
                throw new ExtractError(`Could not build redirect info "${e.toString()}"`);
            }

            throw new ExtractError(`Invalid path "${path}"`);
        }

        unbuild(redirectInfo: PostLoginRedirectInfo) {
            const redirectInfoRaw = this._objectMarshaller.pack(redirectInfo);
            const redirectInfoSer = serializeJavascript(redirectInfoRaw, { isJSON: true });
            return encodeURIComponent(encodeURIComponent(redirectInfoSer));
        }
    }
}
