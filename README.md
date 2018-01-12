# Identity SDK [![Build Status](https://travis-ci.org/hoot-hoot/identity-sdk-js.svg?branch=master)](https://travis-ci.org/hoot-hoot/identity-sdk-js) [![Coverage](https://codecov.io/gh/hoot-hoot/identity-sdk-js/branch/master/graph/badge.svg)](https://codecov.io/gh/hoot-hoot/identity-sdk-js)

The SDK for the identity service. This is meant to be used by both client side and server side code. Some bits are isomorphic and they are found in `/src` directly and are exported via `/src/index.ts` to users. Other bits are server or client specific, and can be found in `/src/server` and `/src/client`, respectively. Both have their own `index.ts` files which export what's needed. The idea is, of course for client code to only reference isomorphic and client code, and server code only isomorphic and server code.

The identity service provides five main functionalities:

- Representations for users and sessions for use by applications.
- A client for interacting with the identity service, if the need arises.
- The definition and implementation of the "auth flow" for users.
- Integration with [auth0](https://auth0.com/). This is a meta-identity provider, abstracting Google/Facebook/Twitter/etc.
- Utilities for other services to make use of the identity service, such as express middleware to ensure a session with a user exists.
