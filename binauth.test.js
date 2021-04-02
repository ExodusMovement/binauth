const sodium = require('@exodus/sodium-crypto')
const crypto = require('crypto')
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
  t.test('issues challenges and tokens', async (t) => {
    const keyPair = await genKeyPair()

    const challenge = await binauth.getChallenge({
      publicKey: keyPair.publicKey,
    })

    t.true(Buffer.isBuffer(challenge), 'returns challenge buffer')

    {
      const opened = await sodium.signOpen({
        signed: challenge,
        publicKey: serverPublicKey,
      })

      t.equal(opened[0], binauth.TYPE_CHALLENGE)
      t.same(opened.slice(1, 33), keyPair.publicKey)
      t.equal(opened.slice(33, 37).readUInt32BE(), Math.floor(Date.now() / 1000))
    }

    const signedChallenge = await sodium.sign({
      message: challenge,
      privateKey: keyPair.privateKey,
    })

    const token = await binauth.getToken({
      signedChallenge: signedChallenge,
      publicKey: keyPair.publicKey,
    })

    t.true(Buffer.isBuffer(token), 'returns auth token buffer')

    {
      const opened = await sodium.signOpen({
        signed: token,
        publicKey: serverPublicKey,
      })

      t.equal(opened[0], binauth.TYPE_TOKEN)
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

    const token = await binauth.getToken({ publicKey, signedChallenge })
    t.equal(
      token.toString('base64'),
      'BabWhb2/N3yMBFeKFTr020lQMTIxnXyNakLO2yXgTIW92vzJLrcDdtb9Uinr80LRUEtrhLzq5eOLOeuAmPSqAQIYpbhAMjTwj+A2QZj7RHXROMzgNxekKFAOeL4rj75KY1/1D7o=',
    )
  })

  t.test('rejects invalid challenges', async (t) => {
    const fixtures = [
      {
        // Bare challenge returned without client signature
        // Type:       1 (challenge)
        // Public Key: 4fbc99e9f8f3b2e3dfbeff13d73856d24ea142d664e55da434a3d052ebf9d8bc
        // Time:       2021-01-06T01:17:46.000Z
        signedChallenge:
          'emmedfnflNfNpO+CpZg9znC2xb0b+KLPAFvflirEVjryAvnBOToErx7wmkByTZV9VmDQIrMd+ywHAIWSE/j7AQFPvJnp+POy49++/xPXOFbSTqFC1mTlXaQ0o9BS6/nYvF/1D7o=',
        publicKey: '4fbc99e9f8f3b2e3dfbeff13d73856d24ea142d664e55da434a3d052ebf9d8bc',
        error: 'challenge failed signature validation',
      },
      {
        // Token signed by client, instead of challenge
        // Type:       2 (token)
        // Public Key: 18a5b8403234f08fe0364198fb4475d138cce03717a428500e78be2b8fbe4a63
        // Time:       2021-01-06T01:17:46.000Z
        signedChallenge:
          'I9h3sDl3rKF9KBHqi0fmHmlJCkpN7kbC+bt2EOulUBOAsgXhebLLEvWWG1Mz2M2OMdYq1ZgE7K/bS/mP6SaaDAWm1oW9vzd8jARXihU69NtJUDEyMZ18jWpCztsl4EyFvdr8yS63A3bW/VIp6/NC0VBLa4S86uXjiznrgJj0qgECGKW4QDI08I/gNkGY+0R10TjM4DcXpChQDni+K4++SmNf9Q+6',
        publicKey: '18a5b8403234f08fe0364198fb4475d138cce03717a428500e78be2b8fbe4a63',
        error: 'incorrect bintoken type',
      },
      {
        // Empty signed by client, instead of challenge
        signedChallenge:
          'vaLJcj8L5cIbccAyiqNorLaKQfTtwSzVRcxu90mVkW4X1ld47gLO522TbjhswDnMbdigI1ttqpwh8FAc8BcpDA==',
        publicKey: '18a5b8403234f08fe0364198fb4475d138cce03717a428500e78be2b8fbe4a63',
        error: 'challenge failed signature validation',
      },
      {
        // Challenge issued on a different, targeted public key
        // Type:       1 (challenge)
        // Public Key: 976caf25cea4362aa287a86fdb6a185ee428822bd8b8736bb4680e9df56bbd0b
        // Time:       2021-01-06T01:17:46.000Z
        signedChallenge:
          'AgPcahVAhoA3PV83ki0EYifoZ/QR7jWKeaSsIRxEb6ayr8T/Vhn5FpUdqdESh/VC6YxwtoCBnxP/Qo4dQd4HBEwU2tbd9V8WVmIdUKV0Pv7YjeaWFgPA0yfx86Tpl5F8SlK1bCSIwvZVpxylUURhSjj4Aylgh3KMKfUkuzSZjgIBl2yvJc6kNiqih6hv22oYXuQogivYuHNrtGgOnfVrvQtf9Q+6',
        publicKey: '18a5b8403234f08fe0364198fb4475d138cce03717a428500e78be2b8fbe4a63',
        error: 'incorrect public key',
      },
      {
        // Challenge issued in the future
        // Type:       1 (challenge)
        // Public Key: 18a5b8403234f08fe0364198fb4475d138cce03717a428500e78be2b8fbe4a63
        // Time:       2100-01-01T00:00:00.000Z
        signedChallenge:
          '6e8F9kU13h08KSrpQMcOFQIMOrsRaxnYeV3nL3byP8ozykZN6FvzCHWvAlgj4GoezlkejmuUiORPlxGqr3gGBeNH4ehbJWbhVbyHPnOk55u+Lyvu+WpIifS/t36dkpaEF0AsZ508BlPy+RFHyxA6UrhDJ0ARrCDrV03GO+sdowQBGKW4QDI08I/gNkGY+0R10TjM4DcXpChQDni+K4++SmP0hlcA',
        publicKey: '18a5b8403234f08fe0364198fb4475d138cce03717a428500e78be2b8fbe4a63',
        error: 'challenge timestamped in the future',
      },
      {
        // Expired challenge
        // Type:       1 (challenge)
        // Public Key: 18a5b8403234f08fe0364198fb4475d138cce03717a428500e78be2b8fbe4a63
        // Time:       2010-01-01T00:00:00.000Z
        signedChallenge:
          'KKlW8CtUDz45EcFMFjQly0qWGgXfhijJ5S6s63qVR1aLXrbeOlWjJtbxv4jiXaSVacYN8JXHdaOfD+T7H+VlDdCm2mwJ/TbYR3DYO/x5WXALA/LoYgqRS5gD4c6ctICwYTPxuQaR+9JeNw4113rmmKeE4F4himVlf9kx8/G0/QoBGKW4QDI08I/gNkGY+0R10TjM4DcXpChQDni+K4++SmNLPTsA',
        publicKey: '18a5b8403234f08fe0364198fb4475d138cce03717a428500e78be2b8fbe4a63',
        error: 'challenge expired',
      },
      {
        // Challenge issued on invalid public key
        // Type:       1 (challenge)
        // Public Key: 00
        // Time:       2021-01-06T01:17:46.000Z
        signedChallenge:
          'hSAlAeN/YagQTHuMxT8hj1qBZ9QVv1WMbTQx3+E1Lcw/8ntb+V5vowEeDy3PaS4hlPSfwfXS/cqFg+64zw3LB+4wq67HVFutLWEj8rW543ujmiZGNyMgf2aXVVCWy1t8xnJn1F0buvXXliN1y8cYk0FfyraZ8jfZclL3JfWqLQEBAF/1D7o=',
        publicKey: '18a5b8403234f08fe0364198fb4475d138cce03717a428500e78be2b8fbe4a63',
        error: 'invalid bintoken length',
      },
    ]

    for (const fixture of fixtures) {
      const signedChallenge = Buffer.from(fixture.signedChallenge, 'base64')
      const publicKey = Buffer.from(fixture.publicKey, 'hex')
      try {
        await binauth.getToken({ signedChallenge, publicKey })
        t.fail(`expected to throw error: ${fixture.error}`)
      } catch (err) {
        t.match(err.message, new RegExp(fixture.error, 'i'), `expected getToken error: ${fixture.error}`)
      }
    }
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

  t.test('rejects invalid tokens', async (t) => {
    const fixtures = [
      {
        // Attempting to use challenge as token
        // Type:       1 (challenge)
        // Public Key: 4fbc99e9f8f3b2e3dfbeff13d73856d24ea142d664e55da434a3d052ebf9d8bc
        // Time:       2021-01-06T01:17:46.000Z
        token: await binauth.getChallenge({
          publicKey: Buffer.from('4fbc99e9f8f3b2e3dfbeff13d73856d24ea142d664e55da434a3d052ebf9d8bc', 'hex'),
        }).then((challenge) => challenge.toString('base64')),
        // 'emmedfnflNfNpO+CpZg9znC2xb0b+KLPAFvflirEVjryAvnBOToErx7wmkByTZV9VmDQIrMd+ywHAIWSE/j7AQFPvJnp+POy49++/xPXOFbSTqFC1mTlXaQ0o9BS6/nYvF/1D7o=',
        error: 'incorrect bintoken type',
      },
      {
        // Attempting to use token with signature from wrong key
        // Type:       2 (token)
        // Public Key: 4fbc99e9f8f3b2e3dfbeff13d73856d24ea142d664e55da434a3d052ebf9d8bc
        // Time:       2021-01-06T01:17:46.000Z
        token:
          'TVt0CbrA+zZdAz0sT6AB9jAqwCbSphcdg0NHlE/NinmPpLGMk07ZWZ840ecw87/ItgNGDRhQcRCgVbFz4SykDQJPvJnp+POy49++/xPXOFbSTqFC1mTlXaQ0o9BS6/nYvF/1D7o=',
        error: 'failed signature validation',
      },
      {
        // Good signature on invalid buffer (too long)
        // Type:       2 (token)
        // Public Key: '00'.repeat(100)
        // Time:       2021-01-06T01:17:46.000Z
        token:
          'aJ22OcH2Tc4jGT1ZOiHdjxvEWRg8dliCUCywzk4ebxKUvT8oJAs13JMDLTN6h3Ny3fBCV7dzWIHyt9ooplM8AgIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAX/UPug==',
        error: 'invalid bintoken length',
      },
      {
        // Good signature on invalid buffer (too short)
        // Type:       2 (token)
        // Public Key: ''
        // Time:       2021-01-06T01:17:46.000Z
        token:
          '9WVmr4AoSQYxg7ZN04Y/Itg+OSk/7ayJdTVMcRQ3qDmpm2nGPx/AaImOVpO2SSfpLd2UyDLIeX9T2HWxFw4lBQJf9Q+6',
        error: 'invalid bintoken length',
      },
      {
        // Attempting to use expired token
        // Type:       2 (token)
        // Public Key: 4fbc99e9f8f3b2e3dfbeff13d73856d24ea142d664e55da434a3d052ebf9d8bc
        // Time:       2020-10-20T00:33:10.000Z
        token:
          'aNde9jIns9kiaxSItGK/EXU+CxpsVMGacSYqh5nRQWuvB5Xnn1xJC3/Izuw/5ancWPp/jAY3XA3zH59sMGX+DQJPvJnp+POy49++/xPXOFbSTqFC1mTlXaQ0o9BS6/nYvF+OMEY=',
        error: 'auth token expired',
      },
      {
        // Attempting to use token created in the future
        // Type:       2 (token)
        // Public Key: 4fbc99e9f8f3b2e3dfbeff13d73856d24ea142d664e55da434a3d052ebf9d8bc
        // Time:       2044-09-11T00:00:00.000Z
        token:
          'qdyV3cDnDqbVE7jk63s6k9nuGCRCFb9FUpyZGvyjAiGgKU46oJlBTXZ/qO8CGa9a6dT7d3H65O3exX63To/ZCwJPvJnp+POy49++/xPXOFbSTqFC1mTlXaQ0o9BS6/nYvIx/ewA=',
        error: 'auth token timestamped in the future',
      },
    ]

    for (const fixture of fixtures) {
      const token = Buffer.from(fixture.token, 'base64')
      try {
        await binauth.verifyToken(token)
        t.fail(`expected to throw error: ${fixture.error}`)
      } catch (err) {
        t.match(err.message, new RegExp(fixture.error, 'i'), fixture.error)
      }
    }
  })

  t.test('rejects invalid input types', async (t) => {
    try {
      await binauth.getChallenge({
        publicKey: '4fbc99e9f8f3b2e3dfbeff13d73856d24ea142d664e55da434a3d052ebf9d8bc',
      })
      t.fail('expected to throw invalid public key')
    } catch (err) {
      t.match(err.message, /invalid public key/, 'expected to fail invalid public key input type')
    }

    try {
      await binauth.getChallenge({
        publicKey: Buffer.alloc(10),
      })
      t.fail('expected to throw invalid public key')
    } catch (err) {
      t.match(err.message, /invalid public key/, 'expected to fail invalid public key input length')
    }

    try {
      await binauth.getToken({
        signedChallenge:
          'hSAlAeN/YagQTHuMxT8hj1qBZ9QVv1WMbTQx3+E1Lcw/8ntb+V5vowEeDy3PaS4hlPSfwfXS/cqFg+64zw3LB+4wq67HVFutLWEj8rW543ujmiZGNyMgf2aXVVCWy1t8xnJn1F0buvXXliN1y8cYk0FfyraZ8jfZclL3JfWqLQEBAF/1D7o=',
        publicKey: Buffer.from('4fbc99e9f8f3b2e3dfbeff13d73856d24ea142d664e55da434a3d052ebf9d8bc', 'hex'),
      })
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
