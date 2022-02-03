require("dotenv").config(); //This line should always be on top and a ".env" file is created to get access to env file.
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const { append } = require("vary");
const mongoose = require("mongoose");
//const encrypt = require("mongoose-encryption");//packace used to encrypt the database
//const md5 = require("md5"); //This is a module of "md5" which is a hashing technique which encrypts the data into hash using md5 technique.
//const bcrypt = require("bcrypt"); //this module will allow the salting in the hashing.

const session = require("express-session"); //To maintain or create sessions
const passport = require("passport");   //To use session and initialise session time
const passportLocalMongoose = require("passport-local-mongoose");

const GoogleStrategy = require("passport-google-oauth20");  //allows to authenticate user using their google account
const findorCreate = require("mongoose-findorcreate");  //used to make "findorCreate" function work


const app = express();

app.use(express.static("public"));

app.set("view engine", "ejs");

app.use(bodyParser.urlencoded({extended: true}));




app.use(session({    //this is placed after all the use and set and is used to create/maintain session using different keys.
    secret: "LONGSTRINGOFKEYTOENCRYPT",
    resave: false,
    saveUninitialized: false  
}));

app.use(passport.initialize()); //used to initialize session for authentication
app.use(passport.session());  //used to initialize the session 


mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    googleId: String,
    secret: String
});

userSchema.plugin(findorCreate);       //used to make findorCreate function work

userSchema.plugin(passportLocalMongoose);    //Plugin to use hash & salt passwords & save our users to MongoDB database.

//const secret = "Secretetextforincription";    //This string is used to encrypt the data of database ("It is basically a key for the encryption")

//const secret = process.env.SECRET; //To access the secrete key from ".env" file.

//userSchema.plugin(encrypt, {secret: secret, encryptedFields: ["password"] }); //this plugin will perform the encrypiton process based on 
                                                                //variable "secret" and it shoud come before creating the model.

//const saltRounds = 10;  //No. of salts that are going to add to original password to get the final hash.

const USER = new mongoose.model("user", userSchema);



passport.use(USER.createStrategy());
passport.serializeUser(function(user, done){
    done(null, user.id);
});   //creates cookies & stuffs info like identification

passport.deserializeUser(function(id, done){
    USER.findById(id, function(err, user){
        done(err, user);
    });
});// destroy cookies & extracts info from cookies



passport.use(new GoogleStrategy({       //google authentication strategy(just like local strategy) it takes following parameters & authenticates user
    clientID: process.env.GOOGLE_CLIENT_ID,    //requires client id from .env file
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",    //if the user is valid then the user will be redirected to this link
},
  function(accessToken, refreshToken, profile, cb) {    //callbakc function that provides the access Token, refresh Token & profile info of registering user.
    USER.findOrCreate({ googleId: profile.id }, function (err, user) {  //finds the user in database & if the user isn't present it creates them.
      return cb(err, user);
    });
  }
));






app.get("/", function(req, res){
    res.render("home");
});

app.get("/auth/google",
    passport.authenticate("google", {scope: ["profile"] })  //uses google strategy to authenticate user
);

app.get("/auth/google/secrets",
passport.authenticate("google", {fialureRedirect: "/login"}),
function(req, res){
res.redirect("/secrets");
});

app.get("/login", function(req, res){
    res.render("login");
});

app.get("/register", function(req, res){
    res.render("register");
});

app.get("/secrets", function(req, res){

        USER.find({"secret": {$ne: null}}, function(err, foundUser){
            if(err){
                console.log(err);
            }else{
                console.log(foundUser);
                res.render("secrets", {userSecrets: foundUser});
            }
        });
});

app.get("/logout", function(req, res){
    req.logout();
    res.redirect("/");
});

app.get("/submit", function(req, res){
    if(req.isAuthenticated()){
        res.render("submit");
    }

    else{
        res.redirect("/login");
    }
});

app.post("/submit", function(req, res){
    const submittedSecret = req.body.secret;
    USER.findById(req.user.id, function(err, foundedUser){
        if(err){
            console.log(err);
        }
        else{
            foundedUser.secret = submittedSecret;
            foundedUser.save(function(){
                res.redirect("/secrets");
            });
        }
    });
});


app.post("/register", function(req, res){

    USER.register({username: req.body.username}, req.body.password, function(err, user){ //this register function is inside the passport & it can create new user & save it with the authentication.

        if(err){
            console.log(err);
            res.redirect("/register");
        }
        else{
            passport.authenticate("local")(req, res, function(){    //authenticate the user & if the user is legit then cookie is created.
                res.redirect("/secrets");
            });
        }

    });


    // bcrypt.hash(req.body.password, saltRounds, function(err, hash){ //bcrypt hash function which takes password("string to be encrypted") & no. of salt rounds and returns the final hash.

    //     const newUser = new USER({
    //         email: req.body.username,
    //         password: hash
    //          //password: md5(req.body.password) //this function will convert the password entered by the user into a hash
    //       });
    //       newUser.save(function(err){
    //           if(!err){
    //               res.render("secrets");
    //           }
    //           else
    //           {
    //               console.log(err);
    //           }
    //       });

    // });
});

app.post("/login", function(req, res){


const newUser = new USER({
    username: req.body.username,
    password: req.body.password
});

req.login(newUser, function(err){
    if(err){
        console.log(err);
    }
    else{
        passport.authenticate("local")(req, res, function(){    //authenticate the user using local strategy & if the user is genuine then cookie is created.
            res.render("secrets");
        });
    }
})



    // const email = req.body.username;
    // const password = req.body.password;
    // //const password = md5(req.body.password); //this function will convert the password entered by the user into a hash
    // USER.findOne({email: email}, function(err, foundedUser){
    //     if(err){
    //         console.log(err);
    //     }
    //     if(foundedUser){
    //         bcrypt.compare(password, foundedUser.password, function(err, result){ //this function will compare the password entered by the user to the hash password present in the password field of database, it returns boolean value.
    //             if(result === true){
    //                 res.render("secrets");
    //             }
    //         });
            
    //     }
    // });
});


app.listen(3000, function(){
    console.log("App running on 3000 port");
});
