require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const massive = require('massive');

const app = express();

app.use(express.json());

let { SERVER_PORT, CONNECTION_STRING, SESSION_SECRET } = process.env;

app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false
  })
);

massive(CONNECTION_STRING).then(db => {
  app.set('db', db);
});

app.post('/auth/signup', async (req, res, next) => {
  const { email, password } = req.body;

  const db = req.app.get('db');

  const user = await db.check_user_exists(email);

  if(user.length){
    res.status(400).send('email already exists in database');
  }

  const saltRounds = 12;
  const salt = await bcrypt.genSalt(saltRounds);
  const hashedPassword = await bcrypt.hash(password, salt);
  const createdUser = await db.create_user([email, hashedPassword]);

  req.session.user = {
    id: createdUser[0].id,
    email: createdUser[0].emai,
  };

  res.status(200).send(req.session.user);
});

app.post('/auth/login', (req, res, next) => {
  console.log(req.body);
  const { email, password } = req.body;
  const db = req.app.get('db');
  db.check_user_exists(email).then(user => {
    if(!user.length){
      res.status(400).send('incorrect email/password')
    } else {
      bcrypt.compare(password, user[0].user_password).then(isAuthenticated => {
        if (isAuthenticated){
          req.session.user = {
            id: user[0].id,
            email: user[0].email
          }
          res.status(200).send(req.session.user);
        } else {
          res.status(400).send('incorrect email/password');
        };
      });
    };
  });
});

app.get('/auth/logout', (req, res) => {
  req.session.destroy();
  res.sendStatus(200);
})

app.listen(SERVER_PORT, () => {
  console.log(`Listening on port: ${SERVER_PORT}`);
});
