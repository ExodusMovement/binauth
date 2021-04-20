const sodium = require('@exodus/sodium-crypto')
const assert = require('./assert')
const bintoken = require('./bintoken')
const { BadRequestError, UnauthorizedError } = require('./errors')

const TYPE_CHALLENGE = 1
const TYPE_TOKEN = 2

const DEFAULT_CHALLENGE_TTL = 60 * 1000 // 1 hour
const DEFAULT_TOKEN_TTL = 24 * 60 * 60 * 1000 // 1 day

const createBinauth = ({
  serverId = '',
  serverPublicKey,
  serverPrivateKey,
  challengeTTL = DEFAULT_CHALLENGE_TTL,
  tokenTTL = DEFAULT_TOKEN_TTL,
}) => {
  assert(typeof serverId === 'string', 'serverId must be a string')
  assert(serverPublicKey, 'must pass serverPublicKey to create binauth service')
  assert(serverPrivateKey, 'must pass serverPrivateKey to create binauth service')
  assert(Number.isInteger(challengeTTL) && challengeTTL > 0, 'invalid challengeTTL, must be positive integer')
  assert(Number.isInteger(tokenTTL) && tokenTTL > 0, 'invalid tokenTTL, must be positive integer')

  serverId = Buffer.from(serverId, 'utf8')
  serverPublicKey = Buffer.from(serverPublicKey)
  serverPrivateKey = Buffer.from(serverPrivateKey)

  const getChallenge = async (publicKey) => {
    assert(Buffer.isBuffer(publicKey) && publicKey.length === 32, 'invalid public key, expected Buffer<32>')

    // We sign the challenge so that the client cannot manipulate it.
    const challengeBuf = await sodium.sign({
      privateKey: serverPrivateKey,
      message: bintoken.toBuffer({
        type: TYPE_CHALLENGE,
        publicKey,
      }),
    })

    return challengeBuf
  }

  const getToken = async (publicKey, signedChallenge) => {
    assert(Buffer.isBuffer(publicKey) && publicKey.length === 32, 'invalid public key, expected Buffer<32>')
    assert(Buffer.isBuffer(signedChallenge), 'invalid signed challenge, expected Buffer')

    let challengeBuf
    try {
      // Unwrap client signature. This ensures the message was signed by the
      // public key that the client claims it was signed by.
      challengeBuf = await sodium.signOpen({
        signed: signedChallenge,
        publicKey,
      })

      // The client may prepend the server ID to the challenge prior to signing, thus ensuring that
      // it is signing a challenge for the correct server. If we find such a prepended server ID,
      // we should strip it. If a server ID was present, but didn't match, we would let it continue
      // and it would fail on the server signature validation step.
      const challengeServerId = challengeBuf.slice(0, serverId.length)
      if (challengeServerId.equals(serverId)) {
        challengeBuf = challengeBuf.slice(serverId.length)
      }

      // Unwrap server signature. This ensures the server issued this challenge
      // and that the data therein was not manipulated since issuance occurred.
      challengeBuf = await sodium.signOpen({
        signed: challengeBuf,
        publicKey: serverPublicKey,
      })
    } catch (err) {
      throw new UnauthorizedError(`challenge failed signature validation: ${err.message}`)
    }

    let challenge
    try {
      challenge = bintoken.fromBuffer(challengeBuf)

      // Ensure that the client is not trying to manipulate the server by passing
      // other signed bintoken messages as the challenge, or by signing with a
      // different public key than the challenge was issued upon.
      assert(challenge.type === TYPE_CHALLENGE, 'incorrect bintoken type')
      assert(challenge.publicKey.equals(publicKey), 'incorrect public key')

      // Should not happen unless the server has a bad clock.
      assert(challenge.time <= Date.now(), 'challenge timestamped in the future')
    } catch (err) {
      throw new BadRequestError(`challenge failed validation: ${err.message}`)
    }

    try {
      assert(challenge.time + challengeTTL >= Date.now(), 'challenge expired')
    } catch (err) {
      throw new UnauthorizedError('challenge expired')
    }

    // The request sender has now been validated as presently having control over the
    // public key given in the challenge. We reply with a token which should afford
    // the bearer the appropriate privileges.
    const authToken = await sodium.sign({
      privateKey: serverPrivateKey,
      message: bintoken.toBuffer({
        type: TYPE_TOKEN,
        publicKey,
      }),
    })

    return authToken
  }

  const verifyToken = async (token) => {
    assert(Buffer.isBuffer(token), 'invalid auth token, expected Buffer')

    // Verify that this token was signed by the server. This prevents manipulation of tokens.
    const tokenBuf = await sodium
      .signOpen({
        signed: token,
        publicKey: serverPublicKey,
      })
      .catch((err) => {
        throw new UnauthorizedError(`token failed signature validation: ${err.message}`)
      })

    let verifiedToken
    try {
      // The public key is not verified here, as in getToken. The server's signature and
      // the TYPE_TOKEN type byte together act as proof-of-authenticity.
      verifiedToken = bintoken.fromBuffer(tokenBuf)
    } catch (err) {
      throw new UnauthorizedError(`token failed to parse: ${err.message}`)
    }

    try {
      assert(verifiedToken.time + tokenTTL >= Date.now(), 'auth token expired')
    } catch (err) {
      throw new UnauthorizedError('auth token expired')
    }

    try {
      // Ensures the client cannot pass other signed bintokens (e.g. challenges) as auth tokens.
      assert(verifiedToken.type === TYPE_TOKEN, 'incorrect bintoken type')

      // Should not happen unless the server has (or had) a bad clock.
      assert(verifiedToken.time <= Date.now(), 'auth token timestamped in the future')
    } catch (err) {
      throw new UnauthorizedError(`token failed security checks: ${err.message}`)
    }

    // The auth token has been validated. The bearer has previously proven that they control this
    // public key. The calling application can decide what rights and responsibilities
    // to bestow upon the client accordingly.
    return verifiedToken.publicKey
  }

  return {
    getChallenge,
    getToken,
    verifyToken,
  }
}

module.exports = createBinauth
