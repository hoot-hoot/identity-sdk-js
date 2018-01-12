import { expect } from 'chai'
import * as HttpStatus from 'http-status-codes'
import 'mocha'
import * as td from 'testdouble'

import { newCheckXsrfTokenMiddleware } from './check-xsrf-token-middleware'
import { XSRF_TOKEN_HEADER_NAME } from '../client'
import { Session } from '../entities'


describe('CheckXsrfTokenMiddleware', () => {
    const theSession = new Session();
    theSession.xsrfToken = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

    const mockReq = td.object({
        session: theSession,
        headers: {},
        log: {
            warn: (_message: string) => { }
        }
    });
    const mockRes = td.object({
        status: (_status: number) => { },
        end: () => { },
        on: () => { },
    });

    afterEach('reset test doubles', () => {
        td.reset();
    });

    it('should pass XSRF-valid request later', () => {
        const checkXsrfTokenMiddleware = newCheckXsrfTokenMiddleware();

        let passedCheck = false;

        (mockReq as any).headers[XSRF_TOKEN_HEADER_NAME] = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

        checkXsrfTokenMiddleware(mockReq as any, mockRes as any, () => { passedCheck = true });

        expect(passedCheck).to.be.true;
    });

    it('should block a request with a missing XSRF token', () => {
        const checkXsrfTokenMiddleware = newCheckXsrfTokenMiddleware();

        let passedCheck = false;

        delete (mockReq as any).headers[XSRF_TOKEN_HEADER_NAME];

        checkXsrfTokenMiddleware(mockReq as any, mockRes as any, () => { passedCheck = true });

        expect(passedCheck).to.be.false;
        td.verify(mockReq.log.warn('Bad XSRF token'));
        td.verify(mockRes.status(HttpStatus.BAD_REQUEST));
        td.verify(mockRes.end());
    });

    const BadTokens = [
        '',
        'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        ',,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,'
    ];

    for (let badToken of BadTokens) {
        it(`should block a request with an invalid XSRF token "${badToken}"`, () => {
            const checkXsrfTokenMiddleware = newCheckXsrfTokenMiddleware();

            let passedCheck = false;

            (mockReq as any).headers[XSRF_TOKEN_HEADER_NAME] = badToken;

            checkXsrfTokenMiddleware(mockReq as any, mockRes as any, () => { passedCheck = true });

            expect(passedCheck).to.be.false;
            td.verify(mockReq.log.warn('Bad XSRF token'));
            td.verify(mockRes.status(HttpStatus.BAD_REQUEST));
            td.verify(mockRes.end());
        });
    }

    it('should block a request with a mismatched XSRF token', () => {
        const checkXsrfTokenMiddleware = newCheckXsrfTokenMiddleware();

        let passedCheck = false;

        (mockReq as any).headers[XSRF_TOKEN_HEADER_NAME] = 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB';

        checkXsrfTokenMiddleware(mockReq as any, mockRes as any, () => { passedCheck = true });

        expect(passedCheck).to.be.false;
        td.verify(mockReq.log.warn('Mismatched XSRF token'));
        td.verify(mockRes.status(HttpStatus.BAD_REQUEST));
        td.verify(mockRes.end());
    });
});
