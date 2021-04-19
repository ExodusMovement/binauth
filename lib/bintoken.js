const assert = require('./assert')

// A bindate is a big-endian binary encoding of a uint32 unix timestamp.
const bindate = {
  toBuffer: (msTime) => {
    const unixTime = Math.floor(msTime / 1000)
    assert(Number.isInteger(unixTime) && unixTime > 0 && unixTime <= 0xFFFFFFFF, 'invalid time')
    const buf = Buffer.alloc(4)
    buf.writeUInt32BE(unixTime)
    return buf
  },

  fromBuffer: (buf) => buf.readUInt32BE() * 1000,
}

// A bintoken is an encoded binary message of a fixed 37-byte length, meant to serve
// as a message signed by client and server. Depending on the type byte, and who
// signed the bintoken, the message may hold different meanings.
//
// E.g. If the type indicates the message is an authentication token, and the
// bintoken is signed by the server's private key, this might statelessly
// guarantee that the server verified (at the time indicated in the bintoken)
// that the bearer of the signed bintoken has control over the given public key.
//
// The binary format simplifies signature verification. Its fixed length simplifies
// decoding & validation, and thus reduces the chance for malicious exploitation.
// It includes three pieces of data:
// - type (1 byte) : a version number which can be used to identify the context of the message.
// - public key (32 bytes) : the public key over which the message holds meaning (as implied by the type).
// - time (4 bytes) : the timestamp (in seconds) when the message was created, encoded as a big-endian uint32.
module.exports = {
  toBuffer: ({ type, publicKey, time = Date.now() }) => {
    assert(Number.isInteger(type) && type >= 0 && type <= 0xff, 'invalid bintoken type')
    assert(Buffer.isBuffer(publicKey) && publicKey.length === 32, 'invalid public key')
    assert(typeof time === 'number' && time > 0, 'invalid time')

    return Buffer.concat([Buffer.from([type]), publicKey, bindate.toBuffer(time)])
  },

  fromBuffer: (buf) => {
    assert(Buffer.isBuffer(buf), 'expected buffer to decode bintoken')
    assert(buf.length === 1 + 32 + 4, 'invalid bintoken length')

    const type = buf[0]
    const publicKey = buf.slice(1, 33)
    const time = bindate.fromBuffer(buf.slice(33, 37))
    assert(typeof time === 'number' && time > 0, 'invalid time')

    return { type, publicKey, time }
  },
}
