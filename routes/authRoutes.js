const express = require('express');
const User = require('../models/User');
const jwt = require('jsonwebtoken');
const router = express.Router();
const authenticate = require('../middlewares/authMiddleware');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');

/////////////////////////////////////////////////////////////////////////////////////////

router.post('/api/account', async (req, res) => {
  try {
    const { login, password, roles, status } = req.body;
    let user = new User({ login, password, roles, status });

    if (roles.includes('ROLE_ADMIN') && !roles.includes('ROLE_USER')) {
      user.roles.push('ROLE_USER');
    }

    await user.save();

    const token = jwt.sign(
      { userId: user._id, roles: user.roles },
      process.env.ACCESS_TOKEN_SECRET, 
      { expiresIn: '1h' } 
    );

     const refreshToken = jwt.sign(
      { userId: user._id, roles: user.roles },
      process.env.REFRESH_TOKEN_SECRET, 
      { expiresIn: '120m' } 
    );

    res.status(201).send({ user, token, refreshToken });
  } catch (error) {
    console.error(error)
    res.status(500).send("Erreur lors de la création de l'utilisateur");
  }
});



////////////////////////////////////////////////////////////////////////////////////////

router.get('/api/account/:uid', authenticate, async (req, res) => {
  const { uid } = req.params;
  const userId = req.user.userId; 
  const isAdmin = req.user.roles.includes('ROLE_ADMIN');

  try {
    
    if (uid !== 'me' && uid !== userId && !isAdmin) {
      return res.status(403).send('Accès refusé');
    }

    const userToRetrieve = uid === 'me' ? userId : uid;
    const user = await User.findById(userToRetrieve);

    if (!user) {
      return res.status(404).send('Utilisateur non trouvé');
    }

    res.status(200).json(user); 
  } catch (error) {
    res.status(500).send('Erreur serveur');
  }
});

///////////////////////////////////////////////////////////////////


router.put('/api/account/:uid', authenticate, async (req, res) => {
  const { uid } = req.params;
  const { login, password, roles, status } = req.body; 
  const userId = req.user.userId;
  const isAdmin = req.user.roles.includes('ROLE_ADMIN');

  try {

    if (uid !== 'me' && uid !== userId && !isAdmin) {
      return res.status(403).send('Accès refusé');
    }

    const userToEdit = uid === 'me' ? userId : uid;
    const user = await User.findById(userToEdit);

    if (!user) {
      return res.status(404).send('Utilisateur non trouvé');
    }

    if (roles && !isAdmin) {
      return res.status(403).send('Seul un admin peut modifier les rôles');
    }

    if (login) user.login = login;
    if (password) user.password = password;
    if (roles) user.roles = roles;
    if (status) user.status = status;

    await user.save();
    res.status(200).json(user);
  } catch (error) {
    res.status(500).send('Erreur serveur');
  }
});


/////////////////////////////////////////////////////////////////////////////////////

router.post('/api/refresh-token/:refreshToken/token', async (req, res) => {
  const { refreshToken } = req.params;

  try {
    
    const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
    const userId = decoded.userId;
    const userRoles = decoded.roles; 

   
    const accessToken = jwt.sign(
      { userId, roles: userRoles },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: '60m' } 
    );


    const newRefreshToken = jwt.sign(
      { userId, roles: userRoles },
      process.env.REFRESH_TOKEN_SECRET,
      { expiresIn: '120m' } 
    );

    res.status(201).json({ accessToken, refreshToken: newRefreshToken });
  } catch (error) {
    res.status(404).send('Token invalide ou inexistant');
  }
});

//////////////////////////////////////////////////////////////////////////////////////


const loginRateLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, 
  max: 3, 
  handler: function (req, res, ) {
    return res.status(429).json({ message: "Trop de tentatives, essayez à nouveau dans 30 minutes" });
  }
});


//////////////////////////////////////////////////////////////////////////////////

router.post('/api/token', loginRateLimiter, async (req, res) => {
  const { login, password } = req.body;


  try {
    const user = await User.findOne({ login });
    console.log(user.password);

    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(404).send('Identifiants non trouvés');
    }

    const accessToken = jwt.sign(
      { userId: user._id, roles: user.roles },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: '60m' }
    );

    const refreshToken = jwt.sign(
      { userId: user._id, roles: user.roles },
      process.env.REFRESH_TOKEN_SECRET,
      { expiresIn: '120m' }
    );

    res.status(201).json({ accessToken, refreshToken });
  } catch (error) {
    res.status(500).send("Erreur serveur");
  }
});


///////////////////////////////////////////////////////////////////////////////

router.get('/api/validate/:accessToken', (req, res) => {
  const { accessToken } = req.params;

  try {
    
    const decoded = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET);
    const currentTime = Date.now() / 1000;
    const expirationDate = new Date(decoded.exp * 1000);
    const timeLeft = decoded.exp - currentTime;

    res.status(200).json({ accessToken, expirationDate, expiresIn: `${timeLeft} seconds` });
    
  } catch (error) {
    res.status(404).send('Token non trouvé / invalide');
  }
});

////////////////////////////////////////////////////////////////////////////////

module.exports = router;
