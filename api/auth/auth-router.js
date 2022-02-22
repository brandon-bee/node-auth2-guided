const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const router = require('express').Router()
const Users = require('../users/users-model.js')
const { checkRole } = require('./auth-middleware')
const { BCRYPT_ROUNDS, TOKEN_SECRET } = require('../../config')

function buildToken(user) {
  const payload = {
    subject: user.id,
    username: user.username,
    role: user.role
  }
  const options = {
    expiresIn: '1d'
  }
  return jwt.sign(payload, TOKEN_SECRET, options)
}

router.post('/register', checkRole, (req, res, next) => {
  let user = req.body

  // bcrypting the password before saving
  const hash = bcrypt.hashSync(user.password, BCRYPT_ROUNDS)
  // never save the plain text password in the db
  user.password = hash

  Users.add(user)
    .then(saved => {
      res.status(201).json({ message: `Great to have you, ${saved.username}` })
    })
    .catch(next) // our custom err handling middleware in server.js will trap this
})

router.post('/login', checkRole, (req, res, next) => {
  let { username, password } = req.body

  Users.findBy({ username })
    .then(([user]) => {
      if (user && bcrypt.compareSync(password, user.password)) {
        const token = buildToken(user)
        res.status(200).json({
          message: `Welcome back ${user.username}...`,
          token
        })
      } else {
        next({ status: 401, message: 'Invalid Credentials' })
      }
    })
    .catch(next)
})

module.exports = router
