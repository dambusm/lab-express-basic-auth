const express = require('express');
const router = express.Router();
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');

const User = require('../models/users');

const saltRounds = 10;

router.get('/signup', function (req, res, next) {
  // Check if user is logged in
  if (req.session.currentUser) {
    console.log('user is already logged in');
    return res.redirect('/');
  }
  const data = {
    messages: req.flash('signup-error')
  };
  res.render('auth/signup', data);
});

router.post('/signup', (req, res, next) => {
  const username = req.body.username;
  const password = req.body.password;
  // Check if user is logged in
  if (req.session.currentUser) {
    return res.redirect('/');
  }

  // Check if username and password params have been sent
  if (!username || !password) {
    req.flash('signup-error', 'Username or password parameter not supplied.');
    return res.redirect('/auth/signup');
  }

  // Check if user exists
  User.findOne({ username: username })
    .then((user) => {
      if (user) {
        // Username exists
        req.flash('signup-error', 'Username already exists.');
        return res.redirect('/auth/signup');
      } else {
        // Username doesn't exist, create the user
        const salt = bcrypt.genSaltSync(saltRounds);
        const hash = bcrypt.hashSync(password, salt);
        const newUser = new User({ username: username, password: hash });
        // Note: if you *return* the result of a function that returns a *promise*, you don't need an extra catch statement, because
        // the error bubbles up to the parent function's catch statement
        return newUser.save().then(result => res.redirect('/auth/login'));
      }
    })
    .catch(next);
});

router.get('/login', function (req, res, next) {
  // Check if user is logged in
  if (req.session.currentUser) {
    return res.redirect('/');
  };
  const data = {
    messages: req.flash('login-error')
  };
  res.render('auth/login', data);
});

router.post('/login', (req, res, next) => {
  const username = req.body.username;
  const password = req.body.password;

  // Check if user is logged in
  if (req.session.currentUser) {
    return res.redirect('/');
  }

  // Check if username and password params have been sent
  if (!username || !password) {
    req.flash('login-error', 'Username or password parameter not supplied.');
    return res.redirect('/auth/login');
  }
  // Check if user exists
  User.findOne({ username: username })
    .then((user) => {
      if (!user) {
        // User doesn't exist
        req.flash('login-error', 'User not found.');
        return res.redirect('/auth/login');
      }
      if (!bcrypt.compareSync(password, user.password)) {
        // Password incorrect
        req.flash('login-error', 'Password incorrect.');
        return res.redirect('/auth/login');
      }

      console.log('log in successful');
      // Save session info
      req.session.currentUser = user;
      res.redirect('/');
    })
    .catch(next);
});

router.post('/logout', (req, res, next) => {
  // Check that the user is logged in
  if (!req.session.currentUser) {
    return res.redirect('/');
  };

  delete req.session.currentUser;
  res.redirect('/');
});

module.exports = router;
