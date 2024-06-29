require('dotenv').config()
const express = require("express") ;
const ejs = require("ejs") ;
const app = express() ;
const mongoose = require("mongoose") ;
const session = require('express-session') ;
const passport = require("passport") ;
const passportLocalMongoose = require("passport-local-mongoose") ;
const GoogleStrategy = require('passport-google-oauth20').Strategy ;
const findOrCreate = require('mongoose-findorcreate') ;

app.set("view engine", "ejs") ;
app.use(express.static("public")) ;
app.use(express.json()) ;
app.use(express.urlencoded({extended:false})) ;

app.use(session({
    secret : "this is a secret." ,
    resave : false ,
    saveUninitialized : false
}))

app.use(passport.initialize()) ;
app.use(passport.session()) ;

mongoose.connect("mongodb://127.0.0.1:27017/userDB") ;

const userSchema = new mongoose.Schema({
    email : String, 
    password : String ,
    googleId : String ,
    secret : String
})

userSchema.plugin(passportLocalMongoose) ;
userSchema.plugin(findOrCreate) ;

const User = new mongoose.model("User", userSchema) ;

passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, {
        id: user.id,
        username: user.username,
        picture: user.picture
      });
    });
  });
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID ,
    clientSecret: process.env.CLIENT_SECRET ,
    callbackURL: "http://localhost:3000/auth/google/secrets" ,
    userProfileURL : "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile) ;
    User.findOrCreate({googleId: profile.id, username: profile.displayName}, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", (req,res) => {
    res.render("home") ;
})

app.get("/auth/google",
  passport.authenticate('google', { scope: ["profile"] })
);

app.get("/auth/google/secrets", 
  passport.authenticate('google', { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect("/secrets");
  });

app.get("/login", (req,res) => {
    res.render("login") ;
})

app.get("/register", (req,res) => {
    res.render("register") ;
})

app.get("/secrets", (req,res) => {
    User.find({secret : {$ne:null}}).then((foundUser) => {
        res.render("secrets", {
            usersWithSecrets : foundUser
        })
    }).catch((err) => {
        console.log(err) ;
    })
})

app.get("/submit", (req,res) => {
    if (req.isAuthenticated()){
        res.render("submit") ;
    } else {
        res.redirect("/login") ;
    }
}) ;

app.post("/submit", (req,res) => {
    const submittedSecret = req.body.secret ;
    console.log(req.user.id) ;
    User.findById(req.user.id).then((foundUser) => {
        foundUser.secret = submittedSecret ;
        foundUser.save() ;
        res.redirect("/secrets") ;
    }).catch((err) => {
        console.log(err) ;
    })
})

app.post("/register", (req,res) => {
    User.register({username : req.body.username}, req.body.password).then((user) => {
        passport.authenticate("local")(req,res, () => {
            res.redirect("/secrets") ;
        })
    }).catch((err) => {
        console.log(err) ;
        res.redirect("/register") ;
    })
})

app.get("/logout", (req,res) => {
    req.logout((err) => {
        if (err) {
            console.log(err) ;
        } else {
            res.redirect("/") ;
        }
    })
})

app.post("/login", (req,res) => {
    const user = new User({
        username : req.body.username ,
        password : req.body.password
    })
    req.login(user, (err) => {
        if (err){
            console.log(err) ;
        } else {
            passport.authenticate("local")(req,res, () => {
                res.redirect("/secrets") ;
            })
        }
    })
})

app.listen(3000, () => {
    console.log("Server is running on port 3000.") ;
})