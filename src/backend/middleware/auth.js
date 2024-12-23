const jwt = require('jsonwebtoken');
const {JWT_SECRET} = require('../../secrets');

module.exports = (req, res, next) => {
  const authHeader = req.get('Authorization');
  if (!authHeader) {
    console.log('no auth!',)
    req.isAuth = false;
    return next();
  }
  const token = authHeader.split(' ')[1];
  let decodedToken;
  try {
    console.log('token',token);

    decodedToken = jwt.verify(token, JWT_SECRET);
    console.log('decodedToken',decodedToken);
  } catch (err) {
    console.log('catch decodedToken!',)
    req.isAuth = false;
    return next();
  }
  if (!decodedToken) {
    console.log('!decodedToken!',)
    req.isAuth = false;
    return next();
  }
  req.userId = decodedToken.userId;
  req.isAuth = true;
  next();
};
