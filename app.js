const express = require("express");
require("dotenv").config();
const app = express();
const path = require("path");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcrypt");
const mongoose = require("mongoose");
const Schema = mongoose.Schema;
const mongoDb = process.env.MONGO_URI;

const bodyParser = require("body-parser");

app.use(express.urlencoded({ extended: false }));
app.use(bodyParser.urlencoded({ extended: false }));

mongoose.connect(mongoDb, { useUnifiedTopology: true, useNewUrlParser: true });
const db = mongoose.connection;
db.on("error", console.error.bind(console, "mongo connection error"));

const MongoDBStore = require("connect-mongodb-session")(session);

var store = new MongoDBStore({
  uri: process.env.MONGO_URI,
  collection: "sessions",
});

// Catch errors
store.on("error", function (error) {
  console.log(error);
});

const authMiddleware = (req, res, next) => {
  if (!req.user) {
    if (!req.session.messages) {
      req.session.messages = [];
    }
    req.session.messages.push("You can't access that page before logon.");
    res.redirect("/");
  } else {
    next();
  }
};

app.get("/sign-up", (req, res) => res.render("sign-up-form"));

const User = mongoose.model(
  "User",
  new Schema({
    username: { type: String, required: true },
    password: { type: String, required: true },
  })
);

app.use(function (req, res, next) {
  res.locals.currentUser = req.user;
  next();
});

app.post("/sign-up", async (req, res, next) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    await User.create({
      username: req.body.username,
      password: hashedPassword,
    });
    res.redirect("/");
  } catch (err) {
    return next(err);
  }
});

app.post(
  "/log-in",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/",
    failureMessage: true,
  })
);

app.get("/", (req, res) => {
  let messages = [];
  if (req.session.messages) {
    messages = req.session.messages;
    req.session.messages = [];
  }
  res.render("index", { messages });
});

app.get("/log-out", (req, res) => {
  req.session.destroy(function (err) {
    res.redirect("/");
  });
});

app.get("/restricted", authMiddleware, (req, res) => {
  if (!req.session.pageCount) {
    req.session.pageCount = 1;
  } else {
    req.session.pageCount++;
  }
  res.render("restricted", { pageCount: req.session.pageCount });
});

passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const user = await User.findOne({ username: username });
      if (!user) {
        return done(null, false, { message: "Incorrect username" });
      }
      bcrypt.compare(password, user.password, (err, result) => {
        if (result) {
          return done(null, user);
        } else {
          return done(null, false, { message: "Incorrect password" });
        }
      });
    } catch (err) {
      return done(err);
    }
  })
);

passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(async function (id, done) {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

app.set("views", __dirname);
app.set("view engine", "ejs");

app.use(passport.initialize());
app.use(passport.session());

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    store: store,
  })
);

app.use(express.urlencoded({ extended: false }));

// app.get("/", (req, res) => res.render("index"));

app.listen(3000, () => console.log("app listening on port 3000!"));
