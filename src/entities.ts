/** The core entities of the identity service. Things like {@link User} and {@link Session}. */

/** Imports. Also so typedoc works correctly. */
import * as r from 'raynor'
import { ExtractError, OptionalOf, MarshalEnum, MarshalFrom, MarshalWith, TryInOrder } from 'raynor'

import { LanguageMarshaller } from '@truesparrow/common-js'


/** A marshaller for the XSRF tokens we use. They're basically 64 random characters. */
export class XsrfTokenMarshaller extends r.StringMarshaller {
    private static readonly _base64RegExp: RegExp = new RegExp('^(?:[A-Za-z0-9+\/]{4})+$');

    filter(s: string): string {
        if (s.length != 64) {
            throw new ExtractError('Expected string to be 64 characters');
        }

        if (!XsrfTokenMarshaller._base64RegExp.test(s)) {
            throw new ExtractError('Expected a base64 string');
        }

        return s;
    }
}


/**
 * A marshaller for user id hashes. Checks that it is a base64 encoded 64 character string.
 */
export class UserIdHashMarshaller extends r.StringMarshaller {
    private static readonly _hexRegExp: RegExp = new RegExp('^[0-9a-f]{64}$');

    filter(s: string): string {
        if (s.length != 64) {
            throw new ExtractError('Expected string to be 64 characters');
        }

        if (!UserIdHashMarshaller._hexRegExp.test(s)) {
            throw new ExtractError('Expected all hex characters');
        }

        return s;
    }
}


/** The state a user can be in. */
export enum UserState {
    /** This should not be used. A default to get us alerted if it happens. */
    Unknown = 0,
    /** The user is active. */
    Active = 1,
    /** The user has removed their account. */
    Removed = 2
}


/** The role the user can have. */
export enum Role {
    /** This should not be used. A default to get us alerted if it happens. */
    Unknown = 0,
    /** A regular user of the platform. */
    Regular = 1,
    /** A manually selected admin. Can usually see details about other users etc. */
    Admin = 2
}


/** Info about a user who has signed-in/up. */
export class User {
    /** The id of the user. */
    @MarshalWith(r.IdMarshaller)
    id: number;

    /** The {@link UserState} the user is in. */
    @MarshalWith(MarshalEnum(UserState, UserState.Unknown))
    state: UserState;

    /** The {@link Role} the user is in. */
    @MarshalWith(MarshalEnum(Role, Role.Unknown))
    role: Role;

    /** The name of the user, obtained from the identity provider. */
    @MarshalWith(r.StringMarshaller)
    name: string;

    /** An uri to the picture of the user, obtained from the identity provider. */
    @MarshalWith(r.SecureWebUriMarshaller)
    pictureUri: string;

    /** The language of the user, as an ISO639 code. */
    @MarshalWith(LanguageMarshaller)
    language: string;

    /** The time the user joined us. */
    @MarshalWith(TryInOrder(r.DateFromTsMarshaller, r.DateMarshaller))
    timeCreated: Date;

    /** The time the last update to the user was done. */
    @MarshalWith(TryInOrder(r.DateFromTsMarshaller, r.DateMarshaller))
    timeLastUpdated: Date;

    /**
     * Whether the user is an admin or not.
     * @return whether the role is {@link Role.Admin} or not.
     */
    isAdmin(): boolean {
        return this.role == Role.Admin;
    }
}


/**
 * Info about a user which is safe to show in a "public" context. This actually means the public
 * views of the application which are accessible to anyone without special privileges.
 */
export class PublicUser extends User {
}

/**
 * Info about a user which can be shown in a "private" context only. This means areas where
 * the user has logged in as themselves, or request handlers for the same.
 */
export class PrivateUser extends User {
    /** Whether the user has agreed to the cookie policy or not. */
    @MarshalWith(r.BooleanMarshaller)
    agreedToCookiePolicy: boolean;

    /**
     * A hash of an externally provided user id, from the identity provider. This is required to
     * identify whatever data that provided supplies as part of the identity flows with what
     * we store in the database. Since the id is sensible information we don't store it expicitly
     * but rather just the hash of it, much like we'd do with a password. The hash is just SHA2
     * however (for the moment), as we don't really need rainbow table protections and the thing
     * does need to be fast (and the source entropy is pretty good).
     */
    @MarshalWith(UserIdHashMarshaller)
    userIdHash: string;
}


/** The state of the {@link Session}. */
export enum SessionState {
    /** A default value which shouldn't be used. */
    Unknown = 0,
    /** The session is active and recent activity has been seen for it, but otherwise the user is unknown. */
    Active = 1,
    /* The session is active and recent activity has been seen for it, and the user is known. */
    ActiveAndLinkedWithUser = 2,
    /**
     * The session has expired. This can happen because the user logs out, or because of some admin action
     * like resetting all the user's sessions when some strange activity has occurred.
     */
    Removed = 3
}


/**
 * Contains data about a session - a series of interactions of a user has with the application.
 * This is meant to be used both in client and server applications, as everything identifying is
 * stored in the {@link SessionToken}.
 */
export class Session {
    /** The current {@link SessionState} of the session. */
    @MarshalWith(MarshalEnum(SessionState))
    state: SessionState;

    /**
     * A token for use against XSRF attacks. The see {@link RequestWithIdentity} for details about
     * how this is used.
     */
    @MarshalWith(XsrfTokenMarshaller)
    xsrfToken: string;

    /** Whether the user has agreed to the cookie policy. */
    @MarshalWith(r.BooleanMarshaller)
    agreedToCookiePolicy: boolean;

    /**
     * An optional {@link PrivateUser}. This will be non-null if the user has done the log-in or
     * sign-in flows.
     */
    @MarshalWith(OptionalOf(MarshalFrom(PrivateUser)))
    user: PrivateUser | null;

    /** The time in UTC when the session was created. */
    @MarshalWith(TryInOrder(r.DateFromTsMarshaller, r.DateMarshaller))
    timeCreated: Date;

    /** The time in UTC when the session was last updated. */
    @MarshalWith(TryInOrder(r.DateFromTsMarshaller, r.DateMarshaller))
    timeLastUpdated: Date;

    /**
     * Checks whether the session has a user with an account or not.
     * @return Whether the session has a user.
     */
    hasUser(): boolean {
        return this.state == SessionState.ActiveAndLinkedWithUser && this.user != null /* superflous */;
    }

    /**
     * Return a more correct value for whether the user has agreed to the cookie policy or not.
     * This checks the {@link user} if it exists, otherwise it looks at the session value. The user
     * value takes precedence.
     * @return Whether the user has agreed to the cookie policy.
     */
    getAgreedToCookiePolicy(): boolean {
        if (this.hasUser()) {
            return (this.user as PrivateUser).agreedToCookiePolicy;
        } else {
            return this.agreedToCookiePolicy;
        }
    }
}
