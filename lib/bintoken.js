const assert = require('./assert')

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
