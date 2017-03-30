var express=require('express');
var ejs=require('ejs');
var bcrypt=require('bcryptjs');
var csurf = require('csurf');
var session=require('express-session');
var bodyParser=require('body-parser');
var mongoose=require('mongoose');
mongoose.connect('mongodb://localhost/BasicAuth');
var Schema = mongoose.Schema,
  ObjectId = Schema.ObjectId;

var userSchema = new Schema({
    id:ObjectId,
    firstName : {type:String},
    lastName  : {type:String},
    email     : {type:String,unique:true},
    password  : {type:String}
});
var User = mongoose.model('users', userSchema);//users is collection name

var app=express();
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
  name: 'session',
  secret: 'keyboard cat',
  resave: false,
  saveUninitialized: true,
}));
app.use(csurf());
app.use(function(req,res,next){
  if(req.session&&req.session.user){
    User.findOne({email:req.session.user.email},function(err,user){
      if(user){
      req.user=user;
      delete req.user.password;
      req.session.user=req.user;
      res.locals.user=req.user;
    }
      next();
    });
   }
   else {
     next();
   }
});
function requireLogin(req,res,next){
  if(!req.user){
    res.redirect('/login');
  }
  else {
    next();
  }
}
app.get('/',function (req,res) {
  res.render('index.ejs',{ csrfToken: req.csrfToken() });
});
app.get('/login',function (req,res) {
  res.render('login.ejs',{ csrfToken: req.csrfToken() });
});
app.post('/login',function (req,res) {
    User.findOne({email:req.body.email},function (err,user) {
      if(!user){
        res.render('login.ejs',{error:"Incorrect email or password"});
      }
      else {
        bcrypt.compare(req.body.password,user.password, function(err, result) {
      if(result === true){
        req.session.user=user;//set-cookie:session=encrypted{email,password,....etc}
      //  console.log(req.session);
        //res.send(req.session);
        res.redirect('/dashboard');
      }
      else {
        res.render('login.ejs',{error:"Incorrect email or password"});
      }
        })
      }
    })
});
app.get('/register',function (req,res) {
  res.render('register.ejs',{ csrfToken: req.csrfToken() });
});
app.post('/register',function (req,res) {
  bcrypt.genSalt(10, function(err, salt) {
    bcrypt.hash(req.body.password, salt, function(err, hash) {
      var user=new User({
        firstName:req.body.firstName,
        lastName:req.body.lastName,
        email:req.body.email,
        password:hash
      });
      user.save(function (err) {
        if (err) {
          var error = 'Something bad happened! Please try again.';
          if (err.code === 11000) {
            error = 'That email is already taken, please try another.';
          }
          res.render('register.ejs', { error: error });
          }
        else {
          res.redirect('/dashboard');
        }

      })
    });
});
});

app.get('/dashboard',requireLogin,function (req,res) {
     res.render('dashboard.ejs');
});
app.get('/logout',function(req,res){
req.session.destroy();
res.clearCookie('session');
res.redirect('/');
});
app.listen(3000);
