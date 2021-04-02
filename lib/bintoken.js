const assert = require('./assert')

const bindate = {
  toBuffer: (msTime) => {
    const unixTime = Math.floor(msTime / 1000)
    const buf = Buffer.alloc(4)
    buf.writeUInt32BE(unixTime)
    return buf
  },

  fromBuffer: (buf) => buf.readUInt32BE() * 1000,
}

module.exports = {
  toBuffer: ({ type, publicKey, time = Date.now() }) => {
    assert(Number.isInteger(type) && type >= 0 && type <= 0xff, 'invalid bintoken type')

    return Buffer.concat([Buffer.from([type]), publicKey, bindate.toBuffer(time)])
  },

  fromBuffer: (buf) => {
    assert(Buffer.isBuffer(buf), 'expected buffer to decode bintoken')
    assert(buf.length === 1 + 32 + 4, 'invalid bintoken length')

    const type = buf[0]
    const publicKey = buf.slice(1, 33)
    const time = bindate.fromBuffer(buf.slice(33, 37))

    return { type, publicKey, time }
  },
}
