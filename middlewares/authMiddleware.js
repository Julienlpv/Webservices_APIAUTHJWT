const jwt = require('jsonwebtoken');

const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1]; 
  
  if (!token) {
    return res.status(401).send('Authentification requise');
  }

  try {
    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET); 
    console.log(process.env.ACCESS_TOKEN_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).send('Token invalide ou expiré');
  }
};

module.exports = authenticate;
