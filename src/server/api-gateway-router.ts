/** Defines a router for translating between external API calls and internal ones. */

/** Imports. Also so typedoc works correctly. */
import { wrap } from 'async-middleware'
import * as bodyParser from 'body-parser'
import * as cookieParser from 'cookie-parser'
import * as express from 'express'
import * as HttpStatus from 'http-status-codes'
import { MarshalFrom } from 'raynor'

import { WebFetcher } from '@truesparrow/common-js'
import { Request } from '@truesparrow/common-server-js'

import {
    SESSION_TOKEN_COOKIE_NAME,
    SESSION_TOKEN_HEADER_NAME
} from '../client'
import { SessionToken } from '../session-token'


/**
 * Create a new router which acts as an API gateway. Code running in a client isn't supposed
 * to call an internal service directly. Rather they call into a backend-for-frontend type service
 * associated with that particular client, and that does the call to the service.
 *
 * The router does a couple of things:
 * - makes sure there's a session token attached to the request.
 * - translates the cookie based token into a header based one. Internal services only speak via
 *   the header approach, while clients will use cookies.
 * - translates the client's call while maintaining all of the caller's properties (headers etc).
 *
 * @note The router has a single path exposed: / which can only be POSTed.
 * @note The router assumes the common middleware is used.
 * @param newOrigin - a value to use for the origin when making calls on behalf of clients.
 * @param webFetcher - a {@link WebFetcher} instance.
 * @return An express router instance which implements the gateway protocol described above.
 */
export function newApiGatewayRouter(newOrigin: string, webFetcher: WebFetcher): express.Router {
    const sessionTokenMarshaller = new (MarshalFrom(SessionToken))();

    const apiGatewayRouter = express.Router();

    apiGatewayRouter.use(bodyParser.json());
    apiGatewayRouter.use(cookieParser());

    apiGatewayRouter.post('/', wrap(async (req: Request, res: express.Response) => {
        // Try to retrieve any side-channel auth information in the request. This can appear
        // either as a cookie with the name SESSION_TOKEN_COOKIE_NAME, or as a header with the name
        // SESSION_TOKEN_HEADER_NAME.
        if (req.cookies[SESSION_TOKEN_COOKIE_NAME] == undefined) {
            req.log.warn('Expected some auth info but there was none');
            res.status(HttpStatus.BAD_REQUEST);
            res.end();
            return;
        }

        const sessionTokenSerialized = req.cookies[SESSION_TOKEN_COOKIE_NAME];

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

        const newOptions = (Object as any).assign({}, req.body['options']);
        if (!newOptions.hasOwnProperty('headers')) {
            newOptions.headers = {};
        }
        newOptions.headers[SESSION_TOKEN_HEADER_NAME] = JSON.stringify(sessionTokenMarshaller.pack(sessionToken as SessionToken));
        newOptions.headers['Origin'] = newOptions.headers['Origin'];
        newOptions.headers['X-Truesparrow-ViaGateway'] = newOrigin;
        const result = await webFetcher.fetch(req.body['uri'], newOptions);
        res.status(result.status);
        res.type('json');
        res.send(await result.text());
        res.end();
    }));

    return apiGatewayRouter;
}
