# Binauth

The `@exodus/binauth` package provides a stateless authentication mechanism, allowing clients to authenticate themselves to the server as a given ed25519 public key. Validation tokens and challenges are issued by signing binary data.

The client must install and use `@exodus/sodium-crypto`, and the server must install both `@exodus/binauth` and `@exodus/sodium-crypto`.

The protocol is described below. Code examples are included, specifying whether the code is running on a server or a client. Transmission of data between client and server could be done in any number of ways: HTTPS requests, websocket messages, etc. This is left as an exercise to the user of this library.

1. The server generates its key pair, and sets up a `binauth` service object from that key pair. The server's keypair should remain consistent so that the authentication tokens given to clients remain valid. This can be done either by saving the entropy used to generate the keys, or by saving the keys themselves and loading them from environment variables. [Using a `.env` file](https://npmjs.com/package/dotenv) is a good way to achieve this without exposing the private key data in your source code.

```js
// Server
const sodium = require('@exodus/sodium-crypto')
const createBinauth = require('@exodus/binauth')

// entropy should be generated randomly and not exposed publicly.
// doing it like this for the sake of demonstration
const entropy = Buffer.from('551a4b322d59e692c7007d8e296ca95b01c22a82f6a428504852ffc7e60675ac', 'hex')

// either the entropy, or the publicKey and privateKey should be saved
const serverKeyPair = await sodium.genSignKeyPair(entropy)

const binauth = createBinauth({
  serverPublicKey: serverKeyPair.publicKey,
  serverPrivateKey: serverKeyPair.privateKey,
})
```

2. The client generates its key pair. This is a public-key-based authentication system, so if the client wants to maintain a consistent identity, they must also maintain a consistent key pair.

```js
// Client
const sodium = require('@exodus/sodium-crypto')

// entropy should be generated randomly and not exposed publicly.
// doing it like this for the sake of demonstration
const entropy = Buffer.from('995007b62f7b2519b1ff34337470db9e323e32ec7118fbe283559add6891df3f', 'hex')

// either the entropy, or the publicKey and privateKey should be saved.
// these keys are Buffer instances.
const { publicKey, privateKey } = await sodium.genSignKeyPair(entropy)
```

3. The client sends its public key to the server.

4. The server issues a challenge on the client's public key. A challenge is a byte array, composed of a version byte specifying that it is a challenge, the client's public key, and a timestamp. The challenge is then signed by the server's private key, so that the server can later verify the challenge is authentic, thereby allowing for statelessness. All this is encapsulated within `binauth.getChallenge`, which returns the signed challenge.

```js
// Server
const challenge = await binauth.getChallenge(publicKey)
console.log(challenge.toString('base64')) // 'AcwBvnPeBHTRw...'
```

5. The server returns the challenge to the client.

6. The client signs the challenge issued by the server. This signature serves as proof to the server that the client owns the private key corresponding to the public key first sent by the client.

```js
// Client
const signedChallenge = await sodium.sign({
  privateKey,
  message: challenge,
})
```

7. The client sends its public key and the signed challenge to the server.

8. The server validates the signed challenge. Therein, a boatload of validation occurs:
  - The server verifies the signed challenge is signed by the public key given by the client.
  - After unwrapping the client's signature, the server's own signature is also verified.
  - The public key from the initial challenge byte array is compared with the one given by the client - they must be equal.
  - The server validates that the initial challenge's version byte is correct.
  - The server validates that the initial challenge's timestamp is within the defined challenge time-to-live (TTL) of the current time, and is not in the future.

If all validation steps succeed, the server signs and issues an authentication token, which will authorize that client as having control of the given public key. The signed authentication token is the same binary format as a signed challenge returned by `binauth.getChallenge`, with a different version byte, the client's public key, and the current timestamp. All of the above is encapsulated within the method `binauth.getToken`.

If validation fails, an error is thrown which may have a `.statusCode` property. `.statusCode` is provided if a planned validation step does not succeed, and the status code describes what class of failure occurred. Right now, it can either be `400` (BadRequest), `401` (Unauthorized), or `undefined`. If `.statusCode` is `undefined`, it should be considered an internal server error, and is probably a bug which should be reported.

```js
// Server
try {
  const authToken = await binauth.getToken(publicKey, signedChallenge)
  console.log(authToken.toString('base64')) // 'UntZvh3hKSPtY3...'
} catch (err) {
  // BadRequest - client is trying to manipulate the server, forge signatures, etc
  if (err.statusCode === 400) throw err

  // Unauthorized - the challenge is not signed properly, or is expired
  if (err.statusCode === 401) throw err

  // InternalServerError - something unexpected went wrong
  throw err
}
```

9. The server returns the authentication token to the client. The client is now 'authenticated', and can pass the authentication token to the server as an HTTP request header, as a URL query parameter, in a request body, in a websocket message, etc.

10. To verify the authentication token, the server calls `binauth.verifyToken(authToken)`. This validates that:
  - the signature on the token came from the server's private key.
  - the token's version byte is that of an authentication token.
  - the token's timestamp is within the defined authentication token time-to-live (TTL) of the current time, and is not in the future.

If the above validation steps succeed, this method returns the 32-byte public key `Buffer`, as included in the authentication token. This is a direct representation of the authenticated client's identity.

If validation fails, an error is thrown which may have a `.statusCode` property. `.statusCode` is provided if a planned validation step does not succeed, and the status code describes what class of failure occurred. Right now, it can only be `401` (Unauthorized) or `undefined`. If `.statusCode` is `undefined`, it should be considered an internal server error, and is probably a bug which should be reported.

```js
// Server
try {
  const publicKey = await binauth.verifyToken(authToken)
} catch (err) {
  // Unauthorized - the token is not signed properly, or is expired
  if (err.statusCode === 401) throw err

  // InternalServerError - something unexpected went wrong
  throw err
}
```


## API Reference

### `createBinauth`

Main Export of `@exodus/binauth`.

This function creates the methods used to create & verify challenges and authentication tokens according to a given public/private key pair.

Parameters:
- `options`: `Object` (required)
  - `serverPublicKey`: `Buffer` (required) - The ED25519 public key of the server.
  - `serverPrivateKey`: `Buffer` (required) - The ED25519 private key of the server.

Returns:
- `binauth`: `Object`
  - `getChallenge`: `Function`
  - `getToken`: `Function`
  - `verifyToken`: `Function`

----------------------

### `getChallenge`

Creates a challenge on the given public key using the

**Parameters**:
- `publicKey`: `Buffer` (required) - The 32-byte ED25519 public key to which the challenge will be issued.

**Returns**:
- `Promise<Buffer>` - The challenge which must be signed by the client's private key.

----------------------

### `getToken`

Tests a signed challenge. Issues an authentication token if the signed challenge correctly proves control of the key pair.

**Parameters**:
- `publicKey`: `Buffer` (required) - The 32-byte ED25519 public key to which the challenge was issued.
- `signedChallenge`: `Buffer` (required) - The challenge from `binauth.getChallenge`, after having signed it with the client's private key.

**Returns**:
- `Promise<Buffer>` - The authentication token which will allow the holder to authenticate, via `binauth.verifyToken`, as the given `publicKey` until it expires, or until the server's key pair is changed.

----------------------

### `verifyToken`

Tests an authentication token. If valid, returns the public key over which the holder of the token has proven control.

**Parameters**:
- `token`: `Buffer` (required) - The authentication token from `binauth.getToken`.

**Returns**:
- `Promise<Buffer>` - The public key which the holder of the authentication token has control.
