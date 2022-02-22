const router = require("express").Router()

const User = require("./users-model.js")

const { restricted } = require('../auth/auth-middleware')

const only = (role) => (req, res, next) => {
  if (req.decodedJwt.role === role) {
    next()
  } else {
    next({
      status: 403,
      message: 'you have no power here'
    })
  }
}

router.get("/", restricted, only('admin'), (req, res, next) => {
  User.find()
    .then(users => {
      res.json(users)
    })
    .catch(next) // our custom err handling middleware in server.js will trap this
})

module.exports = router
