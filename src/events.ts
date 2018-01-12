/**
 * Defines the various events for the entities of the identity type. These types are meant to be
 * serialized, so that influenced some choices (unkown values for enums).
 */

/** Imports. Also so typedoc works correctly. */
import * as r from 'raynor'
import { MarshalEnum, MarshalWith, TryInOrder } from 'raynor'


/**
 * The type of {@link UserEvent}.
 */
export enum UserEventType {
    /** This should not be used. A default to get us alerted if it happens. */
    Unknown = 0,
    /** A user was created. */
    Created = 1,
    /**
     * A user was recreated. Sometimes the user goes through the creation flow, but we already have
     * them. So we use this event to mark that the user was upserted.
     */
    Recreated = 2,
    /** A user has left our system.  */
    Removed = 3,
    /** The user has agreed to our cookie policy. */
    AgreedToCookiePolicy = 4
}


/**
 * An event on a {@link User} entity.
 */
export class UserEvent {
    /** The id of the event. */
    @MarshalWith(r.IdMarshaller)
    id: number;

    /** The {@link UserEventType} of the event. */
    @MarshalWith(MarshalEnum(UserEventType, UserEventType.Unknown))
    type: UserEventType;

    /**
     * The time at which the event happened, as recorded by the server doing the work. It is in UTC.
     * If the event happens as the result of a "request", then the {@link Request.requestTime} should
     * be used.
     */
    @MarshalWith(TryInOrder(r.DateFromTsMarshaller, r.DateMarshaller))
    timestamp: Date;

    /**
     * Data associated with the request which generated this event. Currently there's no extra data
     * for user events.
     */
    @MarshalWith(r.NullMarshaller)
    data: null;
}


/**
 * The type of {@link SessionEvent}.
 */
export enum SessionEventType {
    /** This should not be used. A default to get us alerted if it happens. */
    Unknown = 0,
    /** A session was created. */
    Created = 1,
    /** The session was linked with the user, because the user signed-in/up. */
    LinkedWithUser = 2,
    /**
     * The session has expired. Happens only when the user explicitly logs out or some admin action happens.
     * There's no expiration or anything like that for identity service sessions.
     */
    Removed = 3,
    /** The user has agreed to our cookie policy. */
    AgreedToCookiePolicy = 4
}

/**
 * An event on a {@link Session} entity.
 */
export class SessionEvent {
    /** The id of the event. */
    @MarshalWith(r.IdMarshaller)
    id: number;

    /** The {@link SessionEventType} of the event.*/
    @MarshalWith(MarshalEnum(SessionEventType, SessionEventType.Unknown))
    type: SessionEventType;

    /**
     * The time at which the event happened, as recorded by the server doing the work. It is in UTC.
     * If the event happens as the result of a "request", then the {@link Request.requestTime} should
     * be used.
     */
    @MarshalWith(TryInOrder(r.DateFromTsMarshaller, r.DateMarshaller))
    timestamp: Date;

    /**
     * Data associated with the request which generated this event. Currently there's no extra data for
     * session events.
     */
    @MarshalWith(r.NullMarshaller)
    data: null;
}
