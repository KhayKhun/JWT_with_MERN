require('dotenv').config();
const express = require('express');
const app = express();
const jwt = require('jsonwebtoken');
const cors = require('cors');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
mongoose.connect('mongodb://127.0.0.1:27017/jwtDB')

app.use(bodyParser.urlencoded({extended :true}));
app.use(express.json());

app.use(cors());
const User = require('./modules/user.js');

let refreshTokens = [];

const verify = (req, res,next) => {
    const authHeader = req.headers.authorization
    if(authHeader){
        const token = authHeader.split(" ")[1]
        jwt.verify(token,process.env.ACCESS_TOKEN_SECRET,(err,data) => {
            if(err) {
                res.status(403).send("Token is invalid!")
            }
            else {
                req.user = data;
                next();
            }
        });
    }else{
        console.log("Not authenticated");
        res.status(401).send("Not authenticated!");
    }
};

app.get('/',(req, res)=>{
    res.send("Hello")
})

app.post('/api/refresh',(req,res)=> {
    //Take the refresh token from user
    const refreshToken = req.body.token;
    //Send error if there is no token or is invalid

    if(!refreshToken) res.status(401).send("You're not authenticated");
    else if(!refreshTokens.includes(refreshToken)) res.status(403).send("Token is not valid");

    else{
        jwt.verify(refreshToken,process.env.REFRESH_TOKEN_SECRET,(err,data)=>{
        if(err) console.log(err);
        else{
            User.findById(req.body.userId)
            .then((foundUser)=>{
                if(foundUser) {
                    refreshTokens = refreshTokens.filter(token => token !== refreshToken);

                    const newAccessToken = generateAccessToken(foundUser);
                    const newRefreshToken = generateRefreshToken(foundUser);

                    refreshTokens.push(newRefreshToken);
                    res.send({
                        newAccessToken: newAccessToken,
                        newRefreshToken: newRefreshToken
                    })
                }else res.status(404).send("User not found")
            }).catch((err)=> {
                console.log(err);
                res.sendStatus(500);
            })
        }
    })
};
    //If everything is ok? Create new access token, refresh the token and send to user
});

const generateAccessToken = (prop) => {
    return jwt.sign({
        id: prop._id,
        isAdmin : prop.isAdmin
    },process.env.ACCESS_TOKEN_SECRET,{expiresIn:"3m"});
}
const generateRefreshToken = (prop) => {
    return jwt.sign({id: prop._id,isAdmin : prop.isAdmin},process.env.REFRESH_TOKEN_SECRET);
}

app.post('/api/register',(req,res)=>{
    const {username ,password} = req.body;
    User.findOne({username : username})
    .then(foundUser => {
        if(foundUser){
            res.status(409).send("User already existed")
        }else{
            async function createUser(){
                const newUser = new User({
                    username : username,
                    password : password,
                    isAdmin : false
                })
                await newUser.save().then((response) => {
                    const accessToken =  generateAccessToken(response);
                    const refreshToken = generateRefreshToken(response);
                    refreshTokens.push(refreshToken);
                    const data = {
                        id: response._id,
                        username,
                        isAdmin : false,
                        accessToken,
                        refreshToken
                    }
                    res.json(data);
                }).catch(error => {
                    console.log(error?._message);
                    if (error?._message == 'User validation failed') res.status(400).send(error._message);
                    else res.sendStatus(500);
                });
            }createUser().catch(error => {
                console.log(error);
                res.status(500).send("error on creating user")
            });
        }
    });
})

app.post('/api/login',(req,res)=>{
    const {username ,password} = req.body;
    User.findOne({username : username,password : password})
    .then(foundUser => {
        if(foundUser){
            //Create acess token
            const accessToken =  generateAccessToken(foundUser);

            //Create acess token
            const refreshToken = generateRefreshToken(foundUser);
            refreshTokens.push(refreshToken);
            const data = {
                id: foundUser._id,
                username : foundUser.username,
                isAdmin : foundUser.isAdmin,
                accessToken,
                refreshToken
            }
            res.send(data);
        }else{
            res.sendStatus(404);
        }
    });
})


app.delete('/api/users/:userId',verify,(req,res)=>{
    if(req.user.id === req.params.userId || req.user.isAdmin){
        res.json("User deleted successfully")
    }else{
        res.status(403).json("Can't delete");
    }
})

app.post('/api/logout', verify ,(req,res)=>{
    const refreshToken = req.body.token;
    refreshTokens = refreshTokens.filter(token => token !== refreshToken);
    res.send("Logged out successfully");
})

app.listen(5000,()=> console.log("listening on port 5000"))