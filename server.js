const express = require('express');
const helmet = require('helmet');
const db = require('./database.js');
const User = require('./models/User');
const jwt = require('jsonwebtoken');
const app = express();
require('dotenv').config();


app.use(express.json());
const authRoutes = require('./routes/authRoutes');

console.log('hi');
console.log('secret is', process.env.ACCESS_TOKEN_SECRET);



app.use(helmet());
app.use(authRoutes);




const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Serveur démarré sur le port ${PORT}`));
