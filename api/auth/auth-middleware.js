const jwt = require('jsonwebtoken')
const { TOKEN_SECRET } = require('../../config')
// AUTHENTICATION
const restricted = (req, res, next) => {
  const token = req.headers.authorization
  if (token) {
    jwt.verify(token, TOKEN_SECRET, (err, decoded) => {
      if (err) {
        next({
          status: 401,
          message: 'token bad'
        })
      } else {
        req.decodedJwt = decoded
        next()
      }
    })
  } else {
    next({
      status: 401,
      message: 'we want token!'
    })
  }
}

// AUTHORIZATION
const checkRole = (req, res, next) => {
  next()
}

module.exports = {
  restricted,
  checkRole,
}
