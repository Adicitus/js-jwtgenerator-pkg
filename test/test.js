let JWTGenerator = require('..')
let jwt = require('jsonwebtoken')
let {v4: uuidv4} = require('uuid')
let assert = require('assert')

describe('Default Generator', () => {
    let generator = new JWTGenerator()

    describe('newToken(clientId, options)', () => {
        let result = null

        it('Should return an object.', async () => {
            result = await generator.newToken('client1')
            assert.ok(result)
        })

        it('Should generate a token and associated token record.', () => {
            assert.ok(result.record)
            assert.ok(result.token)
        })
        
        it('Issuer should be this generator', () => {
            assert.equal(result.record.issuer, generator.id)
        })
        
        it('Token should be valid JWT', () => {
            let {header, payload} = jwt.decode(result.token, {complete: true})
            assert.ok(header)
            assert.ok(payload)
        })

        it('header.kid should be same as record.id', () => {
            let {header, payload} = jwt.decode(result.token, {complete: true})
            assert.equal(header.kid, result.record.id)
        })

        it('payload.iss should be same as record.issuer', () => {
            let {header, payload} = jwt.decode(result.token, {complete: true})
            assert.equal(payload.iss, result.record.issuer)
        })

        it('payload.sub should be same as record subject', () => {
            let payload = jwt.decode(result.token)
            assert.equal(payload.sub, result.record.subject)
        })

        it('Should accept custom duration.', async () => {
            let {token, record} = await generator.newToken('client1', { duration: {seconds: 30} })
            let durationMillis = record.expires.toMillis() - record.issued.toMillis()
            let payload = jwt.decode(token)
            assert.equal(durationMillis, (30 * 1000))
            assert.equal(payload.exp - payload.iat, 30)
        })

        it('Should accept custom claims.', async () => {
            let {token, record} = await generator.newToken('client1', { payload: { testClaim: 'test'} })
            let payload = jwt.decode(token)
            assert.ok(payload.testClaim)
            assert.equal(payload.testClaim, 'test')
        })

        it('Should not overwrite fixed claims (iss, sub).', async () => {
            let {token, record} = await generator.newToken('client1', { payload: { iss: 'wrongIssuer', sub: 'wrongSubject'} })
            let payload = jwt.decode(token)
            assert.ok(payload.iss)
            assert.ok(payload.sub)
            assert.equal(payload.iss, record.issuer)
            assert.equal(payload.sub, record.subject)
        })

    })

    describe('generateKeys()', () => {
        it('Should create a new key pair.', async () => {
            let result1 = await generator.newToken('client2')
            generator.generateKeys()
            let result2 = await generator.newToken('client2')
            assert.notEqual(result1.record.key, result2.record.key)
        })
    })

    describe('verifyToken(token, options)', () => {
        describe('If successful:', () => {
            let clientId = 'client1'
            let tokenResult = null
            let verifyResult = null
            let customClaim1 = "TEST1"

            it('Should validate a correct token against its record.', async () => {
                tokenResult = await generator.newToken(clientId, { payload: { customClaim1: customClaim1 } })
                verifyResult = await generator.verifyToken(tokenResult.token, { record: tokenResult.record })
                assert.ok(verifyResult.success)
            })

            it('Should return the subject in the result.', () => {
                assert.equal(verifyResult.subject, clientId)
            })

            it('Should return the payload in the result.', () => {
                assert.ok(verifyResult.payload)
            })

            it('Should retain custom claims in payload.', () => {
                assert.equal(verifyResult.payload.customClaim1, customClaim1)
            })
        })

        describe('If failed:', () => {

            it('Should fail for undefined token.', async () => {
                let r = await generator.verifyToken(undefined)
                assert.ok(!r.success)
                assert.equal(r.status, 'invalidTokenError')
            })

            it('Should fail for null token.', async () => {
                let r = await generator.verifyToken(null)
                assert.ok(!r.success)
                assert.equal(r.status, 'invalidTokenError')
            })

            it('Should fail for empty token.', async () => {
                let r = await generator.verifyToken('')
                assert.ok(!r.success)
                assert.equal(r.status, 'invalidTokenError')
            })

            it('Should fail for non-token string.', async () => {
                let r = await generator.verifyToken(uuidv4())
                assert.ok(!r.success)
                assert.equal(r.status, 'invalidTokenError')
            })

            it('Should fail on expired tokens.', async () =>{
                let r = generator.newToken('oldClient1', { duration: { seconds: -5 } })
                r = await generator.verifyToken(r.token, { record: r.record })
                assert.ok(!r.success)
                assert.equal(r.status, 'invalidTokenError')
            })

            it('Should fail with wrong record.', async () => {
                let r1 = await generator.newToken('client1')
                let r2 = await generator.newToken('client2')
                let r = await generator.verifyToken(r1.token, { record: r2.record })
                assert.ok(!r.success)
                assert.equal(r.status, 'invalidTokenError')
            })

            it('Should fail with no record.', async () => {
                let r = await generator.newToken('client2')
                r = await generator.verifyToken(r.token)
                assert.ok(!r.success)
                assert.equal(r.status, 'noRecordError')
            })

            it('Should fail with invalid record (no subject).', async () => {
                let r = await generator.newToken('client1')
                delete r.record.subject
                r = await generator.verifyToken(r.token, { record: r.record })
                assert.ok(!r.success)
                assert.equal(r.status, 'invalidRecordError')
            })

            it('Should fail with invalid record (no issuer).', async () => {
                let r = await generator.newToken('client1')
                delete r.record.issuer
                r = await generator.verifyToken(r.token, { record: r.record })
                assert.ok(!r.success)
                assert.equal(r.status, 'invalidRecordError')
            })

            it('Should fail with invalid record (no key).', async () => {
                let r = await generator.newToken('client1')
                delete r.record.key
                r = await generator.verifyToken(r.token, { record: r.record })
                assert.ok(!r.success)
                assert.equal(r.status, 'invalidRecordError')
            })
        })
    })

})

describe('Custom Generator', () => {

    it('Should accept a custom ID.', () => {
        let id = uuidv4()
        let g = new JWTGenerator({ id: id })
        assert.equal(g.id, id)
    })

    describe('KeyLifetime', () => {

        describe('0 (Nonce)', () => {
            let g = new JWTGenerator({ id: 'CustomGenerator', keyLifetime: {minutes: 0} })

            it('Should generate a new key for eaach token.', async () => {
                let r1 = await g.newToken('client1')
                let r2 = await g.newToken('client1')

                assert.notEqual(r1.record.key, r2.record.key)
                assert.ok( (await g.verifyToken(r1.token, { record: r1.record })).success )
                assert.ok( (await g.verifyToken(r2.token, { record: r2.record })).success )
            })
        })

        describe('200ms', () => {
            let g = new JWTGenerator({ id: 'CustomGenerator', keyLifetime: {milliseconds: 200} })

            it('Should regenerate keys after 200ms seconds.', async () => {
                let r1 = await g.newToken('client1')
                let r2 = await g.newToken('client1')
                await new Promise(resolve => setTimeout(resolve, 200));
                let r3 = await g.newToken('client1')

                assert.equal(r1.record.key, r2.record.key)
                assert.notEqual(r1.record.key, r3.record.key)
                assert.ok( (await g.verifyToken(r1.token, { record: r1.record })).success )
                assert.ok( (await g.verifyToken(r2.token, { record: r2.record })).success )
                assert.ok( (await g.verifyToken(r3.token, { record: r3.record })).success )
            })
        })
    })

    describe('TokenLifetime: 30 seconds', () => {
        let g = new JWTGenerator({ id: 'CustomGenerator', tokenLifetime: {seconds: 30} })

        it ('Should generate tokens with a lifetime of 30s.', async () => {
            let r = await g.newToken('client1')
            let payload = jwt.decode(r.token)
            assert.equal( (payload.exp - payload.iat), 30)
        })
    })
})
