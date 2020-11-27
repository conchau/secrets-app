//jshint esversion:6
require("dotenv").config(); //must be put right at the top according to documentation
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session")
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const findOrCreate = require("mongoose-findorcreate");


const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));

app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true, useUnifiedTopology: true});
mongoose.set('useCreateIndex', true);

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//Create a new database model for each User with the userSchema
const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

//Establish a session to store user login credentials in a cookie
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

//Google Strategy used to authenticate users via Passport
passport.use(new GoogleStrategy({
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secrets",
  userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},
function(accessToken, refreshToken, profile, cb) {
  User.findOrCreate({ googleId: profile.id }, function (err, user) {
    return cb(err, user);
  });
}
));

//Facebook Strategy used to authenticate users via Passport
passport.use(new FacebookStrategy({
  clientID: process.env.FACEBOOK_APP_ID,
  clientSecret: process.env.FACEBOOK_APP_SECRET,
  callbackURL: "http://localhost:3000/auth/facebook/secrets"
},
function(accessToken, refreshToken, profile, cb) {
  User.findOrCreate({ facebookId: profile.id }, function (err, user) {
    return cb(err, user);
  });
}
));

app.get("/", function(req, res){
  res.render("home");
});

//Sign Up with Google button initiates authentication on Google's servers
app.get("/auth/google",
  //Authenticate user via Google and access their email, profile id, etc
  passport.authenticate("google", { scope: ["profile"] })
);

//Once Google authenticates the user, redirect to authenticate locally
app.get("/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect to secrets route
    res.redirect("/secrets");
  });

//Sign Up with Facebook button initiates authentication on Facebook's servers
app.get("/auth/facebook",
  //Authenticate user via Facebook and access their email, profile id, etc
  passport.authenticate("facebook"));

//Once Facebook authenticates the user, redirect to authenticate locally
app.get("/auth/facebook/secrets",
  passport.authenticate("facebook", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect to secrets route
    res.redirect("/secrets");
  });

app.get("/login", function(req, res){
  res.render("login");
});

app.get("/register", function(req, res){
  res.render("register");
});

app.get("/secrets", function(req, res){
  //Search users collection for all documents where "secret" field is not null
  User.find({"secret": {$ne: null}}, function(err, foundUsers){
    if (err) {
      console.log(err);
    } else {
      //If collection contains users that meet the above condition...
      if (foundUsers) {
        //...render secrets page and pass in foundUsers (needs to be caught by scriplet tag)
        res.render("secrets", {usersWithSecrets: foundUsers});
      }
    }
  });
});

app.get("/submit", function(req, res){
  if (req.isAuthenticated()){
    res.render("submit");
  } else {
    res.redirect("/login");
  }
})

app.get("/logout", function(req, res){
  req.logout();
  res.redirect("/");
});

app.post("/register", function(req, res){

  User.register({username: req.body.username}, req.body.password, function(err, user){
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      })
    }
  })

});

app.post("/login", function(req, res){

  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function(err){
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      })
    }
  })

});

app.post("/submit", function(req, res){
  const submittedSecret = req.body.secret;

  User.findById(req.user.id, function(err, foundUser){
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        foundUser.secret = submittedSecret;
        foundUser.save(function(){
          res.redirect("/secrets");
        });
      }
    }
  });
});


app.listen(3000, function() {
  console.log("Server started on port 3000");
});