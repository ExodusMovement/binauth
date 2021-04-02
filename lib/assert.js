const assert = (cond, message = 'failed assertion') => {
  if (!cond) throw new Error(message)
}

module.exports = assert
