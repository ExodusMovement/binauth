const sodium = require('@exodus/sodium-crypto')
const crypto = require('crypto')
const testVectors = require('./test-vectors')
const createBinauth = require('.')
const test = require('tape')

const serverPublicKey = Buffer.from('f189b0e4cc4d422d681545a2ce79eea824099ec550a058bcd965d6d560ed6574', 'hex')
const serverPrivateKey = Buffer.from(
  'bad6033bf868a9dc01b2dddfbb88251b8fdbd36fb6d9ae7e5931cbf3049dbb5ef189b0e4cc4d422d681545a2ce79eea824099ec550a058bcd965d6d560ed6574',
  'hex',
)

const binauth = createBinauth({ serverPublicKey, serverPrivateKey })

const genKeyPair = (entropy = crypto.randomBytes(32)) => sodium.genSignKeyPair(entropy)

// 2021-01-06T01:17:46.031Z
Date.now = () => 1609895866031

test('binauth service', (t) => {
  t.test('fails on bad initialization parameters', (t) => {
    t.throws(
      () => createBinauth({ serverPublicKey }),
      /must pass serverPrivateKey/,
      'failing to pass serverPrivateKey'
    )
    t.throws(
      () => createBinauth({ serverPrivateKey }),
      /must pass serverPublicKey/,
      'failing to pass serverPublicKey'
    )
    t.throws(
      () => createBinauth({ serverPublicKey, serverPrivateKey, challengeTTL: null }),
      /invalid challengeTTL/,
      'invalid challengeTTL'
    )
    t.throws(
      () => createBinauth({ serverPublicKey, serverPrivateKey, tokenTTL: 'foo' }),
      /invalid tokenTTL/,
      'invalid tokenTTL'
    )
    t.throws(
      () => createBinauth({ serverPublicKey, serverPrivateKey, challengeTTL: -5000 }),
      /invalid challengeTTL/,
      'invalid challengeTTL'
    )
    t.throws(
      () => createBinauth({ serverPublicKey, serverPrivateKey, tokenTTL: 0 }),
      /invalid tokenTTL/,
      'invalid tokenTTL'
    )
    t.throws(
      () => createBinauth({ serverId: 2, serverPublicKey, serverPrivateKey }),
      /serverId must be a string/,
      'invalid serverId'
    )

    t.end()
  })

  t.test('issues challenges and tokens', async (t) => {
    const keyPair = await genKeyPair()

    const challenge = await binauth.getChallenge(keyPair.publicKey)

    t.true(Buffer.isBuffer(challenge), 'returns challenge buffer')

    {
      const opened = await sodium.signOpen({
        signed: challenge,
        publicKey: serverPublicKey,
      })

      t.equal(opened[0], 1) // TYPE_CHALLENGE
      t.same(opened.slice(1, 33), keyPair.publicKey)
      t.equal(opened.slice(33, 37).readUInt32BE(), Math.floor(Date.now() / 1000))
    }

    const signedChallenge = await sodium.sign({
      message: challenge,
      privateKey: keyPair.privateKey,
    })

    const token = await binauth.getToken(keyPair.publicKey, signedChallenge)

    t.true(Buffer.isBuffer(token), 'returns auth token buffer')

    {
      const opened = await sodium.signOpen({
        signed: token,
        publicKey: serverPublicKey,
      })

      t.equal(opened[0], 2) // TYPE_TOKEN
      t.same(opened.slice(1, 33), keyPair.publicKey)
      t.equal(opened.slice(33, 37).readUInt32BE(), Math.floor(Date.now() / 1000))
    }
  })

  t.test('verifies valid signed challenges', async (t) => {
    // Brand new challenge, signed by correct key pairs
    // Type:       1 (challenge)
    // Public Key: 18a5b8403234f08fe0364198fb4475d138cce03717a428500e78be2b8fbe4a63
    // Time:       2021-01-06T01:17:46.000Z
    const signedChallenge = Buffer.from(
      'rVvDDaX9NRVqCuxBOToWjujJbMS2b0He1caovgrFZVx7wbtroXoVnPCw0Xitbys/OsA7v1EuboEHU346c3/QAhwVOBzWGJJguGQQ3SDyvobhqMUBH+PCq8B+XANJFrkQvRlw/gEm/ep+4+/LiiqCkOLgg6y6D9uGm0gXTw5SfAkBGKW4QDI08I/gNkGY+0R10TjM4DcXpChQDni+K4++SmNf9Q+6',
      'base64'
    )
    const publicKey = Buffer.from('18a5b8403234f08fe0364198fb4475d138cce03717a428500e78be2b8fbe4a63', 'hex')

    const token = await binauth.getToken(publicKey, signedChallenge)
    t.equal(
      token.toString('base64'),
      'BabWhb2/N3yMBFeKFTr020lQMTIxnXyNakLO2yXgTIW92vzJLrcDdtb9Uinr80LRUEtrhLzq5eOLOeuAmPSqAQIYpbhAMjTwj+A2QZj7RHXROMzgNxekKFAOeL4rj75KY1/1D7o=',
    )
  })

  t.test('verifies valid tokens', async (t) => {
    {
      // Brand new token
      // Type:       2 (token)
      // Public Key: 4fbc99e9f8f3b2e3dfbeff13d73856d24ea142d664e55da434a3d052ebf9d8bc
      // Time:       2021-01-06T01:17:46.000Z
      const token = Buffer.from(
        'qyBNFMMTsncEgn4k7l9xS01akcjH87MfrNTtevA9U975pfTWQ3WDEzDlae5+irOhoIkvfU0PgbMLjkodOr9MCgJPvJnp+POy49++/xPXOFbSTqFC1mTlXaQ0o9BS6/nYvF/1D7o=',
        'base64'
      )

      const publicKey = await binauth.verifyToken(token)
      t.same(publicKey, Buffer.from('4fbc99e9f8f3b2e3dfbeff13d73856d24ea142d664e55da434a3d052ebf9d8bc', 'hex'))
    }

    {
      // Slightly older token
      // Type:       2 (token)
      // Public Key: 4fbc99e9f8f3b2e3dfbeff13d73856d24ea142d664e55da434a3d052ebf9d8bc
      // Time:       2021-01-05T22:17:46.000Z
      const token = Buffer.from(
        '4UkbxKggoctAvU8IJqxvDuVmFxbTSbPBcEq2RuxdV21tlaMLVgRPU5i5rRyi0/48oc3dOzJbV8nnfLcCRy9xBAJPvJnp+POy49++/xPXOFbSTqFC1mTlXaQ0o9BS6/nYvF/05Yo=',
        'base64'
      )

      const publicKey = await binauth.verifyToken(token)
      t.same(publicKey, Buffer.from('4fbc99e9f8f3b2e3dfbeff13d73856d24ea142d664e55da434a3d052ebf9d8bc', 'hex'))
    }
  })

  t.test('challengeTTL is customizable', async (t) => {
    const binauth = createBinauth({ serverPublicKey, serverPrivateKey, challengeTTL: 1 })

    // Type:       1 (challenge)
    // Public Key: 18a5b8403234f08fe0364198fb4475d138cce03717a428500e78be2b8fbe4a63
    // Time:       2021-01-06T01:17:46.000Z
    const signedChallenge = Buffer.from(
      'rVvDDaX9NRVqCuxBOToWjujJbMS2b0He1caovgrFZVx7wbtroXoVnPCw0Xitbys/OsA7v1EuboEHU346c3/QAhwVOBzWGJJguGQQ3SDyvobhqMUBH+PCq8B+XANJFrkQvRlw/gEm/ep+4+/LiiqCkOLgg6y6D9uGm0gXTw5SfAkBGKW4QDI08I/gNkGY+0R10TjM4DcXpChQDni+K4++SmNf9Q+6',
      'base64'
    )
    const publicKey = Buffer.from('18a5b8403234f08fe0364198fb4475d138cce03717a428500e78be2b8fbe4a63', 'hex')

    try {
      await binauth.getToken(publicKey, signedChallenge)
      t.fail('expected challenge to be expired')
    } catch (err) {
      t.equal(err.statusCode, 401, 'unauthorized due to challenge expiry')
      t.match(err.message, /challenge expired/, '"auth token expired" error message')
    }
  })

  t.test('tokenTTL is customizable', async (t) => {
    const binauth = createBinauth({ serverPublicKey, serverPrivateKey, tokenTTL: 10000 })

    // Type:       2 (token)
    // Public Key: 4fbc99e9f8f3b2e3dfbeff13d73856d24ea142d664e55da434a3d052ebf9d8bc
    // Time:       2021-01-05T22:17:46.000Z
    const token = Buffer.from(
      '4UkbxKggoctAvU8IJqxvDuVmFxbTSbPBcEq2RuxdV21tlaMLVgRPU5i5rRyi0/48oc3dOzJbV8nnfLcCRy9xBAJPvJnp+POy49++/xPXOFbSTqFC1mTlXaQ0o9BS6/nYvF/05Yo=',
      'base64'
    )

    try {
      await binauth.verifyToken(token)
      t.fail('expected token to be expired')
    } catch (err) {
      t.equal(err.statusCode, 401, 'unauthorized due to token expiry')
      t.match(err.message, /token expired/, '"auth token expired" error message')
    }
  })

  t.test('validates cross-server signature-reuse attacks by specifying serverId', async (t) => {
    const { publicKey, privateKey } = await genKeyPair()

    const binauth = createBinauth({ serverId: 'Server B', serverPublicKey, serverPrivateKey })
    const challenge = await binauth.getChallenge(publicKey)

    // This imaginary client believes it is talking to Server A, so it signs the challenge
    // using 'Server A' as the server ID. This prevents a takeover of Server A from
    // impacting client keypairs which are reused on Server B.
    const signedChallenge = await sodium.sign({
      privateKey,
      message: Buffer.concat([
        Buffer.from('Server A'),
        challenge,
      ])
    })

    try {
      await binauth.getToken(publicKey, signedChallenge)
      t.fail('expected to throw invalid server ID')
    } catch (err) {
      t.match(
        err.message,
        /incorrect signature for the given public key/,
        'expected signature validation to fail due to server ID mismatch'
      )
    }
  })

  t.test('rejects invalid input types', async (t) => {
    try {
      await binauth.getChallenge('4fbc99e9f8f3b2e3dfbeff13d73856d24ea142d664e55da434a3d052ebf9d8bc')
      t.fail('expected to throw invalid public key')
    } catch (err) {
      t.match(err.message, /invalid public key/, 'expected to fail invalid public key input type')
    }

    try {
      await binauth.getChallenge(Buffer.alloc(10))
      t.fail('expected to throw invalid public key')
    } catch (err) {
      t.match(err.message, /invalid public key/, 'expected to fail invalid public key input length')
    }

    try {
      await binauth.getToken(
        Buffer.from('4fbc99e9f8f3b2e3dfbeff13d73856d24ea142d664e55da434a3d052ebf9d8bc', 'hex'),
        'hSAlAeN/YagQTHuMxT8hj1qBZ9QVv1WMbTQx3+E1Lcw/8ntb+V5vowEeDy3PaS4hlPSfwfXS/cqFg+64zw3LB+4wq67HVFutLWEj8rW543ujmiZGNyMgf2aXVVCWy1t8xnJn1F0buvXXliN1y8cYk0FfyraZ8jfZclL3JfWqLQEBAF/1D7o='
      )
      t.fail('expected to throw invalid signedChallenge')
    } catch (err) {
      t.match(err.message, /invalid signed challenge/, 'expected to fail invalid signed challenge input type')
    }

    try {
      await binauth.verifyToken('qdyV3cDnDqbVE7jk63s6k9nuGCRCFb9FUpyZGvyjAiGgKU46oJlBTXZ')
      t.fail('expected to throw invalid auth token')
    } catch (err) {
      t.match(err.message, /invalid auth token/, 'expected to fail invalid auth token input type')
    }
  })
})

test('official test vectors', (t) => {
  t.test('valid', async (t) => {
    for (let i = 0; i < testVectors.valid.length; i++) {
      const testVector = testVectors.valid[i]

      Date.now = () => testVector.time
      const serverPrivateKey = Buffer.from(testVector.serverPrivateKey, 'hex')
      const serverPublicKey = Buffer.from(testVector.serverPublicKey, 'hex')
      const clientPublicKey = Buffer.from(testVector.clientPublicKey, 'hex')
      const clientPrivateKey = Buffer.from(testVector.clientPrivateKey, 'hex')
      const expectedChallenge = Buffer.from(testVector.challenge, 'base64')
      const expectedSignedChallenge = Buffer.from(testVector.signedChallenge, 'base64')
      const expectedToken = Buffer.from(testVector.token, 'base64')

      const { serverId } = testVector

      const binauth = createBinauth({ serverId, serverPrivateKey, serverPublicKey })
      let challenge = await binauth.getChallenge(clientPublicKey)
      t.equal(
        challenge.toString('base64'),
        expectedChallenge.toString('base64'),
        `test vectors -> valid[${i}]: challenge matches`
      )

      if (serverId) {
        challenge = Buffer.concat([Buffer.from(serverId), challenge])
      }

      const signedChallenge = await sodium.sign({
        privateKey: clientPrivateKey,
        message: challenge,
      })

      t.equal(
        signedChallenge.toString('base64'),
        expectedSignedChallenge.toString('base64'),
        `test vectors -> valid[${i}]: signed challenge matches`
      )

      const token = await binauth.getToken(clientPublicKey, signedChallenge)

      t.equal(
        token.toString('base64'),
        expectedToken.toString('base64'),
        `test vectors -> valid[${i}]: auth token matches`
      )
    }
  })

  t.test('invalid signed challenges', async (t) => {
    for (let i = 0; i < testVectors.invalidSignedChallenges.length; i++) {
      const testVector = testVectors.invalidSignedChallenges[i]

      Date.now = () => testVector.time
      const serverPrivateKey = Buffer.from(testVector.serverPrivateKey, 'hex')
      const serverPublicKey = Buffer.from(testVector.serverPublicKey, 'hex')
      const clientPublicKey = Buffer.from(testVector.clientPublicKey, 'hex')
      const signedChallenge = Buffer.from(testVector.signedChallenge, 'base64')

      const { challengeTTL, serverId } = testVector
      const binauth = createBinauth({ serverId, serverPrivateKey, serverPublicKey, challengeTTL })

      const comment = `test vectors -> invalidSignedChallenges[${i}]: ${testVector.comment}`
      try {
        await binauth.getToken(clientPublicKey, signedChallenge)
        t.fail(`${comment} - expected getToken to throw`)
      } catch (err) {
        t.match(err.message, new RegExp(testVector.error), comment)
      }
    }
  })

  t.test('invalid auth tokens', async (t) => {
    for (let i = 0; i < testVectors.invalidTokens.length; i++) {
      const testVector = testVectors.invalidTokens[i]

      Date.now = () => testVector.time
      const serverPrivateKey = Buffer.from(testVector.serverPrivateKey, 'hex')
      const serverPublicKey = Buffer.from(testVector.serverPublicKey, 'hex')
      const clientPublicKey = Buffer.from(testVector.clientPublicKey, 'hex')
      const token = Buffer.from(testVector.token, 'base64')

      const { tokenTTL, serverId } = testVector
      const binauth = createBinauth({ serverId, serverPrivateKey, serverPublicKey, tokenTTL })

      const comment = `test vectors -> invalidTokens[${i}]: ${testVector.comment}`
      try {
        await binauth.verifyToken(token)
        t.fail(`${comment} - expected verifyToken to throw`)
      } catch (err) {
        t.match(err.message, new RegExp(testVector.error), comment)
      }
    }
  })
})
