/** Defines middleware for protecting against XSRF attacks. */

/** Imports. Also so typedoc works correctly. */
import * as express from 'express'
import * as HttpStatus from 'http-status-codes'

import { RequestWithIdentity } from '../request'
import { XsrfTokenMarshaller } from '../entities'
import { XSRF_TOKEN_HEADER_NAME } from '../client'


/**
 * Create an express middleware for protection against XSRF attacks, for the identity service.
 * Needs to apply after the session middleware, since it depends on a session existing. What this
 * does is simply check the contents of the header given by {@link XSRF_TOKEN_HEADER_NAME} against
 * the XSRF token attached to the session. If they match the request is allowed to further stages.
 * @return A connect middleware doing all of the above.
 */
export function newCheckXsrfTokenMiddleware() {
    const xsrfTokenMarshaller = new XsrfTokenMarshaller();

    return function(req: RequestWithIdentity, res: express.Response, next: express.NextFunction): any {
        try {
            const xsrfTokenRaw = req.headers[XSRF_TOKEN_HEADER_NAME];
            const xsrfToken = xsrfTokenMarshaller.extract(xsrfTokenRaw);

            if (xsrfToken != req.session.xsrfToken) {
                req.log.warn('Mismatched XSRF token');
                res.status(HttpStatus.BAD_REQUEST);
                res.end();
                return;
            }
        } catch (e) {
            req.log.warn('Bad XSRF token');
            res.status(HttpStatus.BAD_REQUEST);
            res.end();
            return;
        }

        // Fire away.
        next();
    };
}
