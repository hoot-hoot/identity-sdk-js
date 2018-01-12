import { expect } from 'chai'
import 'mocha'

import { UserTokenMarshaller, SessionToken } from './session-token'


describe('UserTokenMarshaller', () => {
    const UserTokens = [
        'abcd',
        'ABC0123-FADA',
        '__this__is__a__token'
    ];

    const EmptyUserTokens = [
        ''
    ];

    const BadUserTokens = [
        '()',
        '::',
        'abá',
        'FEFE:'
    ];

    describe('extract', () => {
        for (let userToken of UserTokens) {
            it(`should parse "${userToken}"`, () => {
                const userTokenMarhaller = new UserTokenMarshaller();

                expect(userTokenMarhaller.extract(userToken)).to.eql(userToken);
            });
        }

        for (let userToken of EmptyUserTokens) {
            it(`should throw for empty "${userToken}"`, () => {
                const userTokenMarhaller = new UserTokenMarshaller();

                expect(() => userTokenMarhaller.extract(userToken)).to.throw('Expected a string to be non-empty');
            });
        }

        for (let userToken of BadUserTokens) {
            it(`should throw for empty "${userToken}"`, () => {
                const userTokenMarhaller = new UserTokenMarshaller();

                expect(() => userTokenMarhaller.extract(userToken)).to.throw('Should only contain alphanumerics');
            });
        }
    });

    describe('pack', () => {
        for (let userToken of UserTokens) {
            it(`should pack "${userToken}"`, () => {
                const userTokenMarshaller = new UserTokenMarshaller();

                expect(userTokenMarshaller.pack(userToken)).to.eql(userToken);
            });
        }
    });
});


describe('SessionToken', () => {
    it('should construct with no user token', () => {
        const sessionToken = new SessionToken('aaa-bbb');

        expect(sessionToken.sessionId).to.eql('aaa-bbb');
        expect(sessionToken.userToken).to.be.null;
    });

    it('should construct with user token', () => {
        const sessionToken = new SessionToken('aaa-bbb', 'xAbc');

        expect(sessionToken.sessionId).to.eql('aaa-bbb');
        expect(sessionToken.userToken).to.eql('xAbc');
    });
});
