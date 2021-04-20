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

  // Unauthorized - the challenge is not signed properly, or is expired.
  // Maybe the server changed key pairs.
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
  // Unauthorized - the token is not signed properly, or is expired.
  // Maybe the server changed key pairs.
  if (err.statusCode === 401) throw err

  // InternalServerError - something unexpected went wrong
  throw err
}
```

## Security Considerations

**Data transmission between server & client should be done only via a secure channel.** This library does not attempt to provide MitM protection. That is delegated to the transport layer (i.e. TLS).

---------

If you plan to use this authentication protocol on more than one server, each talking to common clients, then **you should ensure that client and server key pairs are NOT reused** between different server-client contexts.

Reusing _server_ key pairs would mean that authentication tokens and challenges valid for one server are also valid for the other, and if one has a vulnerability, then they both do. This should be avoided as it provides zero benefit.

Reusing _client_ key pairs could result in escalation attacks, whereby control of one server can enable an attacker to impersonate common clients on other servers.

For example, let's say _Server A_ and _Server B_ both talk to the same client, who uses the same public key pair for both servers. Let's imagine Server A is taken over by an attacker. The client authenticating with Server A will send up their public key to get a challenge. Server A could use that public key to fetch a challenge from Server B, and give that challenge to the client. The client would blindly sign it, and send the signed challenge to Server A. **The attacker controlling Server A can now use the signed challenge to generate an authentication token and thus impersonate the client on Server B.**

The most natural solution is to create new key pairs for every new server-client context, on both sides. This ensures that if auth tokens or keys are exposed for one context, or even if a server is taken over, it cannot affect the authentication context of others.

### Server ID

However, if you cannot guarantee that key pairs will not be reused, there is another safety mechanism. You can pass `serverId` to the `createBinauth` function. This option **should be used if you plan to reuse client key pairs across multiple servers.** Each server must set a unique and consistent `serverId` when initializing `binauth`.

Clients talking to that server _should_ prepend the appropriate `serverId` onto challenges prior to signing. This prevents signed challenges from being valid across different servers. Here is an example from a test case:

```js
const challenge = await binauth.getChallenge(publicKey)

// This imaginary client believes it is talking to server123, so it signs the challenge
// using 'server123' as the server ID. This prevents a takeover of server123 from
// impacting client keypairs which are reused on some other server, e.g. 'server999'.
const signedChallenge = await sodium.sign({
  privateKey,
  message: Buffer.concat([
    Buffer.from('server123'),
    challenge,
  ])
})
```

Even if the server specifies a `serverId`, the client can also choose to be server-agnostic, and just sign the challenge as-is. The server would still accept the signed challenge even without a prepended `serverId`. In this case, the client's public-key-identity would be vulnerable to the escalation attack described above.

## FAQ

**You keep mentioning that this system is _stateless._ What does that mean?**

A _stateful_ authentication system would involve storing tokens or login-type events in a stateful data storage mechanism (a database, in-memory, on-disk files, etc). An example of a stateful auth system would be one which validates identity by whichever means, but then must store that validation event in its storage, so that it doesn't forget about it - like writing down a note that says 'token ABC is held by user X'. When using X comes back later with token ABC, trying to authenticate, it would look up the given bearer token 'ABC' in its storage. It would check the token's expiration, and finally confirm that we should endow the bearer with the identity of user X.

Contrastingly, a _stateless_ authentication system requires no storage. Instead we have a set of pure functions which each make guarantees about the data they receive & return, each step of the way waiting for input from the client. To achieve statelessness, all necessary data is encapsulated in the input and output values of these functions. Once we reach the end of `verifyToken` without error, the procedure has proven the client has had control of a specific public key pair within a verified time span, and that they should be treated as having that control for a configurable amount of time (`tokenTTL`).

-------------

**Why is statelessness useful?**

Common situations where statelessness is desirable:
- serverless architecture (such as AWS Lambda) where filesystems and persistent memory cannot be relied upon.
- distributed systems where agreement on a single source of truth is challenging.
- potato systems with limited disk space and memory available for storage.

Stateless authentication is useful for scaling. If your server expects to have to authenticate very large numbers of clients, a _stateful_ authentication system might put severe strain on your server's storage mechanism. _Stateless_ authentication, on the other hand, will scale upwards with processing power, and can be neatly parallelized without any race conditions.

Stateless authentication might also help simplify your project. For example, you may choose stateless authentication in order to free your server of need for a database.

-------------

**How is statelessness deficient?**

Some authentication protocols are not possible with stateless authentication. Since there is no state, there are no 'sessions' which could be selectively revoked. Singleton authentication is impossible, because clients necessarily can create unlimited numbers of authentication tokens (provided they can prove control of a public key pair).

Once a challenge or authentication token is issued, it is valid until it expires, or _until the server's key pair is changed._

-------------

**Why not sign every request? Or have the client generate their own 'challenge' and sign it, to save on the number of requests?**

We make the client sign a server-issued challenge so that the client can be unopinionated as to the server-side authentication implementation. The client need only fetch a challenge, sign it, and give it to the server in exchange for a bearer authentication token. They client doesn't need to know what the challenge _is,_ nor anything about how the server authenticates their signature on it. It doesn't need to decide what data to sign, how to serialize that data, etc. There is no concern about the client's clock being wrong, because the server provides and signs timestamps in the token's message body. In short, it leaves much more room for flexibility on the server-side.

-------------

**How should a compromised server key be handled?**

If a server's private key (or the entropy used to generate a key pair) is compromised, it must be changed ASAP on any server instances using the same key pair.

After changing the server key pair, all previously issued challenges and authentication tokens will be invalid under the new key pair. This is because the signatures on them are from the old compromised key pair, which would fail upon signature validation with the new key pair. The server must handle when clients submit challenges and tokens with the wrong signatures correctly, and indicate to the client that they must re-authenticate.

In other words, the server should return a `401` when the server's own signature is detected to be incorrect. When the client gets a `401`, it should run through the authentication process anew to ensure it gets a challenge and authentication token from the new server key pair.

-------------

**How should compromised client keys be handled?**

Once compromised, a private key cannot be un-compromised. This means that the public-key identity is no longer secure, and there's no way to re-secure it. The client must rotate its keys and authenticate as if it were an entirely new client.

As such, clients should take pains to keep their private keys safe, commensurate with the privileges available to them once authenticated. You may also wish to consider implementing a 'self-destruct' feature available to the client in the event it believes the private key has been compromised. Self-destructing would amount to account deletion: purging any sensitive data that the authenticated client would have access to, and revocation of any abilities it once posessed.

-------------

**How should compromised authentication tokens be handled?**

Compromised authentication tokens are not nearly as dangerous as compromised client keys, because they expire. After expiring, they can no longer be used, but in the meantime there is no way to selectively revoke them.

If a client's auth token was somehow leaked without their private key being leaked, the only way to revoke it is to deauthenticate all users by rotating the server key pair. This would invalidate _all_ tokens and challenges, everywhere, simultaneously. Valid clients should seamlessly reautheticate via the corresponding client implementation.

_Alternatively, blocklists of tokens could theoretically be imposed prior to `getToken` / `verifyToken` calls, but that is not recommended, as maintaining such blocklists could be challenging._

If your implementation carries exposure risk for authentication tokens, it is recommended to set a short `tokenTTL` so that exposed tokens carry minimal risk.


## API Reference

### `createBinauth`

Main Export of `@exodus/binauth`.

This function creates the methods used to create & verify challenges and authentication tokens according to a given public/private key pair.

Parameters:
- `options`: `Object` (required)
  - `serverPublicKey`: `Buffer` (required) - The ED25519 public key of the server.
  - `serverPrivateKey`: `Buffer` (required) - The ED25519 private key of the server.
  - `serverId`: `String` (optional) - A string identifying the server. See [Server ID instructions](#server-id).
  - `challengeTTL`: `Number` (optional) - The number of milliseconds before newly issued challenges will expire. Defaults to 1 hour. If passed, must be a positive integer.
  - `tokenTTL`: `Number` (optional) - The number of milliseconds before newly minted authentication tokens will expire. Defaults to 1 day. If passed, must be a positive integer.

Returns:
- `binauth`: `Object`
  - `getChallenge`: `Function`
  - `getToken`: `Function`
  - `verifyToken`: `Function`

----------------------

### `getChallenge`

Issues a challenge on the given public key by signing a message which includes the given public key and a timestamp. The client will have `challengeTTL` milliseconds to sign the resulting challenge data `Buffer`, and send the signed challenge to the server for consumption by `getToken`.

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
