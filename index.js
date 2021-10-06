const express = require('express')
const app = express()
const port = 3000
const passport = require('passport');
const BasicStrategy = require('passport-http').BasicStrategy 
const bodyParser = require('body-parser')
const bcrypt = require('bcryptjs')
const {uuid} = require('uuidv4');
const multer = require('multer')
const upload = multer({dest: 'uploads/'})
const Ajv = require("ajv")
const ajv = new Ajv()
const userInfoSchema = require('./schemas/userInfo.schema.json');
const userInfoValidator = ajv.compile(userInfoSchema)


const userDB = []
const postings = [] 

app.set('port', (process.env.PORT || 80)); 
app.use(express.json());

passport.use(new BasicStrategy(
    (username, password, done) => {
        console.log('Basic strategy params, username: ' + username + ' , password: ' + password);

        //CREDENTIAL CHECK
        const searchResult = userDB.find(user => {
            if(user.username === username) {
                if(bcrypt.compareSync(password, user.password)) {
                    return true;
                }
            }
        })
        if(searchResult != undefined) {
            done(null, searchResult); //successfully autenticated
        } else {
            done(null, false); //no credential match
        }

    }
));

//NEW USER 
app.post('/register', userInfoValidateMw, (req, res) => {
    const salt = bcrypt.genSaltSync(6);
    const hashedPassword = bcrypt.hashSync(req.body.password, salt);
    const newUser = {
        username: req.body.username,
        name: req.body.name,
        birthDate: req.body.birthDate,
        address: {
            streetAddress: req.body.streetAddress,
            postalCode: req.body.postalCode,
            city: req.body.city,
            country: req.body.country,
        },
        email: req.body.email,
        password: hashedPassword

    }
    //ADD NEW USER TO DATABASE
    userDB.push(newUser); //toimii
    res.sendStatus(201);

    res.send(newUser.userID);
})


app.get('/', (req, res) => {
  res.send('BCI-project | created by Veera Vaananen')
})


//LOGIN 
const jwt = require('jsonwebtoken')
const JwtStrategy = require("passport-jwt").Strategy
const ExtractJwt = require("passport-jwt").ExtractJwt
const secrets = require('./secrets.json')
const options = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: secrets.jwtSignKey
}

app.post('/login', passport.authenticate('basic', { session: false}), (req, res) => {
    res.send(200);
})

//DELETE USER 
app.delete('/users/:userID', passport.authenticate('jwt', { session: false }), (req, res) => {
    if(req.params.id === req.userDB.userID) {
        const user = userDB.find(u => u.userID === req.params.id)
        if(user === undefined) {
            res.sendStatus(404)
        } else {
            var index = userDB.indexOf(user);
            userDB.splice(index, 1);
            res.send(200);
        }
    }
})

//CREATE NEW POST 
app.post('/postings', passport.authenticate('basic', {session: false}), parser.array('photos', 4), function (req, res, next) {

var params = true
var todayDate = new Date().toISOString().slice(0, 10);
if (req.body.title == undefined || req.body.category == undefined || req.body.askingPrice == undefined)
{
    params = false
    res.sendStatus(400)
}

try {
    list = []
    for (let i = 0; i < 4; i ++)
    {
        try {
            list.push(req.files[i].url)
        }
        catch (error) {
        }
    }
} catch (error) {
    console.log(error);
    res.send(400);
}
const newPost = {
    postID : uuid(),
    title: req.body.title,
    description: req.body.description,
    category: req.body.category,
    location: req.body.location,
    images : list,
    price: req.body.price,
    dateOfPosting: todayDate,
    deliveryType: req.body.deliveryType,
    sellersName: req.body.sellersName,
    contactInformation: req.body.contactInformation
    }
if (params == true)
{
    postings.push(newPost)
    res.sendStatus(201);
}
res.send(newPost.postID);
})

//MODIFY POST
app.put('/users/postings', passport.authenticate('jwt', { session: false }), parser.array('photos', 4), 
(req, res) => {
    post = postings.find(p => p.postID === req.params.postID)
    if(post === undefined) {
        res.sendStatus(404)
    }else {
        if(post.userID === req.user.userID) {
            post.title = req.body.title,
            post.description = req.body.description,
            post.category = req.body.category,
            post.location = req.body.location,
            post.images = list,
            post.price = req.body.price,
            post.dateOfPosting = todayDate,
            post.deliveryType = req.body.deliveryType,
            post.sellersName = req.body.sellersName,
            post.contactInformation = req.body.contactInformation

            res.sendStatus(200)
         } else {
             res.sendStatus(401)
      }
    }
})

//DELETE POST
app.delete('/users/postings', passport.authenticate('jwt', { session: false }), parser.array('photos', 4), 
(req, res) => {
    const post = postings.find(p => p.postID === req.params.postID)
    if(post === undefined) {
        res.sendStatus(404)
    } else {
        if(post.userID === req.userDB.userID) {
            var index = postings.indexOf(post);
            postings.splice(index, 1);
            res.sendStatus(200)
        } else {
            res.sendStatus(401)
        }
    }
})

//GET POSTS BASED ON "CATEGORY", "LOCATION" & "DATE OF POSTING"
app.get('/postings/search', (req, res) => {
    let searchPostings = postings;
    if('category' in req.query != false) {
        searchPostings = searchPostings.find(p => p.category == req.query.category)
    }
    if('location' in req.query != false) {
        searchPostings = searchPostings.find(p => p.location == req.query.location)
    }
    if('dateOfPosting' in req.query != false) {
        searchPostings = searchPostings.find(p => p.dateOfPosting == req.query.dateOfPosting)
    }
    res.send(searchPostings)
})

/*
app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`)
})
*/

app.listen(app.get('port'), function() {
    console.log('Example app listening at http://localhost')
  })