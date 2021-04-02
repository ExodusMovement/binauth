class BadRequestError extends Error {
  get statusCode() {
    return 400
  }
}

class UnauthorizedError extends Error {
  get statusCode() {
    return 401
  }
}

module.exports = { BadRequestError, UnauthorizedError }
