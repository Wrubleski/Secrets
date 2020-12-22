//jshint esversion:6

require('dotenv').config();
const express = require("express");
const mongoose = require("mongoose");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const encrypt = require("mongoose-encryption");
// const bcrypt = require("bcrypt");
// const saltRounds = 10;
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");


app = express();
app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({extended: true}));


app.use(session({
    secret: "Our little secret",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true, useUnifiedTopology: true});
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});


userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
// userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ["password"]});


const User = new mongoose.model("User", userSchema);


passport.use(User.createStrategy());

passport.serializeUser((user, done)=>{
    done(null, user.id);
});

passport.deserializeUser((id, done)=>{
    User.findById(id, (err, user)=>{
        done(err, user);
    });
});

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

app.get('/', (req, res)=>{
    res.render("home");
});


app.get('/login', (req, res)=>{
    res.render("login");
});

app.get("/submit", (req, res)=>{
    if (req.isAuthenticated()){
        res.render("submit");
    } else {
        res.redirect("/login");
    }
});

app.post("/submit", (req, res)=>{
    const submittedSecret = req.body.secret;
    User.findById(req.user.id, (err, foundUser)=>{
        if (err) {
            console.log(err);
        } else {
            if (foundUser) {
                foundUser.secret = submittedSecret;
                foundUser.save(()=>{
                    res.redirect("/secrets");
                });
            }
        }
    });

});

app.get('/register', (req, res)=>{
    res.render("register");
});

app.get("/auth/google", 
    passport.authenticate("google", {scope: ["profile"]})
);

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
});


app.get("/secrets", (req, res)=>{
    User.find({"secret": {$ne: null}}, (err, foundUser)=>{
        if (err) {
            console.log(err);
        } else {
            if (foundUser) {
                res.render("secrets", {usersWithSecrets: foundUser});
            }
        }
    });
});

app.post("/register", (req, res)=>{

    User.register({username: req.body.username}, req.body.password, (err, user)=>{
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, ()=>{
                res.redirect("/secrets");
            });
        }
    });



    // Usando bcrypt
    // bcrypt.hash(req.body.password, saltRounds, (err, hash)=>{
    //     const newUser = User({
    //         email: req.body.username,
    //         password: hash
    //     });
    
    //     newUser.save((err)=>{
    //         if (!err){
    //             res.render("secrets");
    //         } else {
    //             res.send(err);
    //         }
    //     });
    // });
});

app.post("/login", (req, res)=>{


    const user = new User({
        username : req.body.username,
        password: req.body.password
    });

    req.login(user, (err)=>{
        if (err){
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, ()=>{
                res.redirect("/secrets");
            });
        }
    });




    // Usando bcrypt
    // const userName = req.body.username;
    // const password = req.body.password;

    // User.findOne({email: userName}, (err, found)=>{
    //     if (err){
    //         res.send(err);
    //     } else {
    //         if (found) {

    //             bcrypt.compare(password, found.password, (err, response)=>{
    //                 if(response){
    //                     res.render("secrets");
    //                 }
    //             })
                
    //         } else {
    //             res.send('User not found.');
    //         }
    //     }
    // });

});


app.get('/logout', (req, res)=>{
    req.logout();
    res.redirect("/");
});

app.listen(3000, ()=>{
    console.log("Listening on port 3000");
});