const mongoose = require('mongoose');

const uri = 'mongodb://127.0.0.1:27017/apiAuth';
mongoose.connect(uri);

const db = mongoose.connection;

db.on('error', console.error.bind(console, 'Erreur de connexion MongoDB:'));
db.once('open', function() {
  console.log('Connecté à MongoDB');
});

module.exports = db;