var bodyParser = require('body-parser');
var bcrypt = require('bcryptjs');
var csrf = require('csurf');
var express = require ('express');
var mongoose = require('mongoose');
var session = require('client-sessions');

var Schema = mongoose.Schema;
var ObjectId = Schema.ObjectId;

var User = mongoose.model('User', new Schema({
    id: ObjectId,
    name: String,
    email: { type: String, unique: true},
    password: String
}));

var app = express();
app.set('view engine', 'jade');
app.locals.pretty = true;

//Connect to MongoDB ( auth - database )
mongoose.connect('mongodb://localhost/auth');

//middleware to read the request body
app.use(bodyParser.urlencoded( {extended:true}) );

app.use(session({
    cookieName: 'session',
    secret: 'dsakhuijewiujdij323jkasdlOIDSAa',
    duration: 30 * 60 * 1000,
    activeDuration: 5 * 60 * 1000,
    httpOnly: true, //prevent browser js to access cookies
    ephemeral:true, //delete this cookie when the browser is closed
}));

app.use(csrf());

app.use(function(req, res, next){
    if(req.session && req.session.user){
        User.findOne( { email: req.session.user.email }, function(err, user){
            if(user){
                req.user = user;
                delete req.user.password;
                req.session.user = req.user;
                res.locals.user = req.user;
            }
            next();
        });
    } else {
        next();
    }
});

function requireLogin(req, res, next){
    if(!req.user){
        res.redirect('/login');
    } else {
        next();
    }
};

app.get('/', function(request, response){
    response.render('index.jade');
});

app.get('/login', function(req, res){
    res.render('login.jade', { csrfToken: req.csrfToken() });
});

app.post('/login', function(req, res){
    User.findOne({ email: req.body.email }, function(err, user){
        if(!user){
            res.render('login.jade', {error: 'Invalid email or password'});
        }else{
            if(bcrypt.compareSync(req.body.password, user.password)){
                req.session.user = user;
                res.redirect('/dashboard');
            }
            else{
                res.render('login.jade', {error: 'Invalid email or password'});
            }
        }
    })
});

app.get('/register', function(req, res){
    res.render('register.jade', { csrfToken: req.csrfToken() });
});

app.post('/register', function(req, res){
    var salt = bcrypt.genSaltSync(10);
    var hash = bcrypt.hashSync(req.body.password, salt);
    var user = new User({
        name: req.body.name,
        email: req.body.email,
        password: hash
    });

    user.save(function(err){
        if(err){
            var err = "Error occured..";
            if(err.code === 11000){
                error = "Email already exists !";
            }
            res.render('register.jade', {error: error});
        } else {
            res.redirect('/dashboard');
        }
    });
});

app.get('/dashboard', requireLogin , function(req, res){
    res.render('dashboard.jade');
});

app.get('/logout', function(req, res){
    req.session.reset();
    res.redirect('/');
});

app.listen(3000);