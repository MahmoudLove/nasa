const path = require('path');
const https = require('https');
const fs = require('fs');
const express = require('express');
const helmet = require('helmet');
const passport = require('passport');
const { Strategy } = require('passport-google-oauth20');
const cookieSession = require('cookie-session');
require('dotenv').config();

const PORT = 3000;

const config = {
  CLIENT_ID: process.env.CLIENT_ID,
  CLIENT_SECRET: process.env.CLIENT_SECRET,
  COOKIE_KEY_1: process.env.COOKIE_KEY_1,
  COOKIE_KEY_2: process.env.COOKIE_KEY_2,
};

const AUTH_OPTIONS = {
  callbackURL: '/auth/google/callback',
  clientID: config.CLIENT_ID,
  clientSecret: config.CLIENT_SECRET,
};

function verifyCallBack(accessToken, refreshToken, profile, done) {
  console.log(`google account :`, profile);
  done(null, profile); //used in cookie
}

//SAVE DATA TO COOKIE
passport.serializeUser((user, done) => {
  done(null, user.id); // with this only step we write the hal profile and read it back when cookie is send from browser in deserialize
});
//READ DATA FROM A COOKIE
passport.deserializeUser((id, done) => {
  done(null, id);
});

passport.use(new Strategy(AUTH_OPTIONS, verifyCallBack));
const app = express();
app.use(helmet());
app.use(
  cookieSession({
    name: 'session',
    maxAge: 24 * 60 * 60 * 1000,
    keys: [config.COOKIE_KEY_1, config.COOKIE_KEY_2],
  })
);
app.use(passport.initialize());
app.use(passport.session()); // AUTHENTICATE THE SESSION BY THE KEYS / ALLOW DESERIAIZE USER TO BE CALLED WHICH ALLOW REQ.USER TO BE
function checkLoggedIn(req, res, next) {
  console.log('user is :', req.user); // set by pass.session middle ware and written by passport.deserialize
  const loggedIn = req.isAuthenticated() && req.user;
  if (!loggedIn)
    return res.status(401).json({
      error: 'must be looged in',
    });
  next();
}

app.get(
  '/auth/google',
  passport.authenticate('google', {
    scope: ['email'],
  })
);

app.get(
  '/auth/google/callback',
  passport.authenticate('google', {
    successRedirect: '/',
    failureRedirect: '/failure',
    session: true,
  }),
  (req, res) => {
    console.log('google called us back yay');
  }
);

app.get('/failure', (req, res, next) => {
  res.send('failed to load ');
});

app.get('/auth/logout', (req, res, next) => {
  req.logout(); // remove req.user and remove any session or set  BASE64 coded session instead
  return res.redirect('/');
});

app.get('/secret', checkLoggedIn, (req, res) => {
  return res.send('the most secret on planet earth');
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

https
  .createServer(
    {
      key: fs.readFileSync('key.pem'),
      cert: fs.readFileSync('cert.pem'),
    },
    app
  )
  .listen(PORT, () => {
    console.log(`server is on port : ${PORT}`);
  });
