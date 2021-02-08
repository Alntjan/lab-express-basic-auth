// routes/auth.routes.js

const express = require("express");
const router = express.Router();
const bcryptjs = require("bcryptjs");
const saltRounds = 10;
const User = require("../models/User.model");
const RoutGuard = require("../midleware/routeGuard");

// .get() route ==> to display the signup form to users
router.get("/login", (req, res) => res.render("auth/login"));

router.post("/login", (req, res, next) => {
  const { username, password } = req.body;
  if (username === "" || password === "") {
    res.render("auth/login", {
      errorMessage: "please enter both user and passoword",
    });
    return;
  }

  User.findOne({ username })
    .then((user) => {
      if (!user) {
        res.render("auth/login", { errorMessage: "User is not registerd." });
        return;
      } else if (bcryptjs.compareSync(password, user.passwordHash)) {
        req.session.currentUser = user;
        console.log(user);
        res.redirect("/user-profile");
      } else {
        res.render("auth/login", { errorMessage: "Wrong password." });
      }
    })
    .catch((err) => next(err));
});

router.get("/user-profile", (req, res) => {
  console.log(req.session);
  res.render("auth/user", { user: req.session.currentUser });
});

router.post("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/user-profile");
});

router.get("/main", RoutGuard, (req, res) => {
  res.render("auth/main");
});

router.get("/private", RoutGuard, (req, res) => {
  res.render("auth/private");
});

router.get("/signup", (req, res) => res.render("auth/signup"));

// .post() route ==> to process form data
router.post("/signup", (req, res, next) => {
  console.log("The form data: ", req.body);
  const { username, password } = req.body;

  bcryptjs
    .genSalt(saltRounds)
    .then((salt) => bcryptjs.hash(password, salt))
    .then((passwordHash) => {
      console.log(passwordHash);
      return User.create({ username, passwordHash });
    })
    .then((user) => {
      console.log(user);
      res.redirect("/");
    })
    .catch((err) => next(err));
});

module.exports = router;
