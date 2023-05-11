const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    username : {
        type : String,
        required : true,
        minLength : 3,
        maxLength : 15
    },
    password : {
        type : String,
        required : true,
        minLength : 5,
        maxLength : 20
    },
    isAdmin : Boolean,
});

const User = mongoose.model('User',userSchema);

module.exports = User;