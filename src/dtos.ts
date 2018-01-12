/** Data-transfer objects for the identity service. */

/** Imports. Also so typedoc works correctly. */
import { ArrayOf, MarshalFrom, MarshalWith } from 'raynor'

import { PublicUser, Session } from './entities'
import { SessionToken } from './session-token'


/** A response with both a {@link Session} and {@link SessionToken}. */
export class SessionAndTokenResponse {
    /** The {@link SessionToken} identifying the session. */
    @MarshalWith(MarshalFrom(SessionToken))
    sessionToken: SessionToken;

    /** The {@link Session} information. */
    @MarshalWith(MarshalFrom(Session))
    session: Session;
}


/** A response with just a {@link Session}. */
export class SessionResponse {
    /** The {@link Session} information. */
    @MarshalWith(MarshalFrom(Session))
    session: Session;
}


/** A response with information about a lot of users. */
export class UsersInfoResponse {
    /** The set of information about users. */
    @MarshalWith(ArrayOf(MarshalFrom(PublicUser)))
    usersInfo: PublicUser[];
}
