import { expect } from 'chai'
import 'mocha'
import * as serializeJavascript from 'serialize-javascript'

import { PathMatch, PostLoginRedirectInfo, PostLoginRedirectInfoMarshaller } from './auth-flow'


describe('PostLoginRedirectInfo', () => {
    it('is constructed properly', () => {
        const info = new PostLoginRedirectInfo('/a/path');
        expect(info.path).to.eql('/a/path');
    });

    describe('marshalling', () => {
        const allowedPaths: PathMatch[] = [
            {path: '/', mode: 'full'},
            {path: '/admin', mode: 'full'},
            {path: '/admin/', mode: 'prefix'}
        ];

        const postLoginRedirectInfos = [
            [quickEncode({path: '/'}), new PostLoginRedirectInfo('/')],
            [quickEncode({path: '/admin'}), new PostLoginRedirectInfo('/admin')],
            [quickEncode({path: '/admin/foo'}), new PostLoginRedirectInfo('/admin/foo')],
            [quickEncode({path: '/admin/foo?id=10'}), new PostLoginRedirectInfo('/admin/foo?id=10')]
        ];

        const badPathPostLoginRedirectInfos = [
            [quickEncode({path: '/a-bad-path'}), '/a-bad-path'],
            [quickEncode({path: '/xadmin'}), '/xadmin'],
            [quickEncode({path: '/admin-foo'}), '/admin-foo']
        ];

        const simplyBadPostLoginRedirectInfos = [
            quickEncode({path: 'admin'}),
            quickEncode({path: ''}),
            quickEncode({}),
            quickEncode({pathx: '/admin'}),
            'a-badly-encoded-thing'
        ];

        describe('extract', () => {
            for (let [raw, extracted] of postLoginRedirectInfos) {
                it(`should extract "${raw}"`, () => {
                    const marshaller = new (PostLoginRedirectInfoMarshaller(allowedPaths))();
                    expect(marshaller.extract(raw)).to.eql(extracted);
                })
            }

            for (let [badExample, badPath] of badPathPostLoginRedirectInfos) {
                it(`should throw for not allowed path "${badExample}"`, () => {
                    const marshaller = new (PostLoginRedirectInfoMarshaller(allowedPaths))();
                    expect(() => marshaller.extract(badExample)).to.throw(`Invalid path "${badPath}"`);
                });
            }

            for (let badExample of simplyBadPostLoginRedirectInfos) {
                it(`should throw for not allowed path "${badExample}"`, () => {
                    const marshaller = new (PostLoginRedirectInfoMarshaller(allowedPaths))();
                    expect(() => marshaller.extract(badExample)).to.throw().that.has.property('message').which.matches(/^Could not build redirect info/);
                });
            }
        });

        describe('pack', () => {
            for (let [raw, extracted] of postLoginRedirectInfos) {
                it(`should produce the same input for "${raw}"`, () => {
                    const marshaller = new (PostLoginRedirectInfoMarshaller(allowedPaths))();
                    expect(marshaller.pack(extracted as PostLoginRedirectInfo)).to.eql(raw);
                })
            }
        })

        describe('extract and pack', () => {
            for (let [example] of postLoginRedirectInfos) {
                it(`should be opposites for "${example}"`, () => {
                    const marshaller = new (PostLoginRedirectInfoMarshaller(allowedPaths))();

                    const raw = example;
                    const extracted = marshaller.extract(raw);
                    const packed = marshaller.pack(extracted);

                    expect(packed).to.eql(raw);
                });
            }
        });

        function quickEncode(obj: any): string {
            return encodeURIComponent(encodeURIComponent(serializeJavascript(obj)));
        }
    });
});
