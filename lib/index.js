const sodium = require('@exodus/sodium-crypto')
const assert = require('./assert')
const bintoken = require('./bintoken')
const { BadRequestError, UnauthorizedError } = require('./errors')

const TYPE_CHALLENGE = 1
const TYPE_TOKEN = 2

const DEFAULT_CHALLENGE_TTL = 60 * 1000 // 1 hour
const DEFAULT_TOKEN_TTL = 24 * 60 * 60 * 1000 // 1 day

const createBinauth = ({
  serverPublicKey,
  serverPrivateKey,
  challengeTTL = DEFAULT_CHALLENGE_TTL,
  tokenTTL = DEFAULT_TOKEN_TTL,
}) => {
  assert(serverPublicKey, 'must pass serverPublicKey to create binauth service')
  assert(serverPrivateKey, 'must pass serverPrivateKey to create binauth service')
  assert(Number.isInteger(challengeTTL) && challengeTTL > 0, 'invalid challengeTTL, must be positive integer')
  assert(Number.isInteger(tokenTTL) && tokenTTL > 0, 'invalid tokenTTL, must be positive integer')

  serverPublicKey = Buffer.from(serverPublicKey)
  serverPrivateKey = Buffer.from(serverPrivateKey)

  const getChallenge = async (publicKey) => {
    assert(Buffer.isBuffer(publicKey) && publicKey.length === 32, 'invalid public key, expected Buffer<32>')

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
      // Unwrap client signature
      challengeBuf = await sodium.signOpen({
        signed: signedChallenge,
        publicKey,
      })

      // Unwrap server signature
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

      assert(challenge.type === TYPE_CHALLENGE, 'incorrect bintoken type')
      assert(challenge.time <= Date.now(), 'challenge timestamped in the future')
      assert(challenge.publicKey.equals(publicKey), 'incorrect public key')
    } catch (err) {
      throw new BadRequestError(`challenge failed validation: ${err.message}`)
    }

    try {
      assert(challenge.time + challengeTTL >= Date.now(), 'challenge expired')
    } catch (err) {
      throw new UnauthorizedError('challenge expired')
    }

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
      // public key is not verified here, this is the first time when we receive it
      verifiedToken = bintoken.fromBuffer(tokenBuf)
    } catch (err) {
      throw new UnauthorizedError(`token failed to parse: ${err.message}`)
    }

    try {
      assert(verifiedToken.time + tokenTTL >= Date.now(), 'auth token expired')
    } catch (err) {
      throw new UnauthorizedError('auth token expired')
    }

    // should not happen
    try {
      assert(verifiedToken.type === TYPE_TOKEN, 'incorrect bintoken type')
      assert(verifiedToken.time <= Date.now(), 'auth token timestamped in the future')
    } catch (err) {
      throw new UnauthorizedError(`token failed security checks: ${err.message}`)
    }

    return verifiedToken.publicKey
  }

  return {
    getChallenge,
    getToken,
    verifyToken,
  }
}

module.exports = createBinauth
