const jwt = require("jsonwebtoken");
const { JWT_SECRET } = require("../../config");

// AUTHENTICATION //identity
const restricted = (req, res, next) => {
  const token = req.headers.authorization;
  if (token) {
    jwt.verify(token,JWT_SECRET,(err,decodedToken)=> {
      if (err) {
        next({status : 401, message : `token ba: ${err.message}`}) //too much info for prod
      } else {
        req.decodedJwt = decodedToken,

        next();
      }
    })
  } else {
    next({status : 401, message : "what? no token?" })
  }
}

// AUTHORIZATION //permissions
const checkRole = role => (req, res, next) => {
  if (req.decodedJwt && req.decodedJwt.role === role) {
    next();
  } else {
    next({ status : 403, message : "bad bad authorization"})
  }
}

module.exports = {
  restricted,
  checkRole,
}
