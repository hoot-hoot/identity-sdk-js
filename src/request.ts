/** Defines {@link RequestWithIdentity}. */

/** Imports. Also so typedoc works correctly. */
import { Request } from '@truesparrow/common-server-js'

import { Session } from './entities'
import { SessionToken } from './session-token'


/**
 * The `truesparrow` standard request with attached identity information. It is an extension of the standard {@link Request},
 * which is based on the {@link express.Request}, which is itself based off of the node one.
 */
export interface RequestWithIdentity extends Request {
    /**
     * The {@link SessionToken} attached to this request. This is present on _every_ request of this type, without
     * question and identifies the associated {@link Session} this request is part of. The session middleware is
     * in charge of ensuring this exists and associates the actual {@link Session}.
     */
    sessionToken: SessionToken;
    /**
     * The {@link Session} this request is part of. The session middleware is in charge of ensuring this exists.
     */
    session: Session;
}
