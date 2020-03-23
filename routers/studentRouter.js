const express = require('express');
const {Student} = require('../models/student');
const router = express.Router();
//const {checkAdminEmails,checkEmail,checkUser,checkAdminLocs} = require('../tools/toolExports');

router.post('/',(req,res) => {
    const {firstName,lastName} = req.body;

    return Student.create({
        firstName,
        lastName
    })

    .then(student => {
        return res.json({
            code:200,
            message:'Student created',
            fullName:student.fullName
        });
    })

    .catch(err => {
        console.log('error ',err);
        if(err.message.includes('E11000')){
            return res.json({
                code:401,
                message:'User already exists'
            });
        }
        return res.json({
            code:500,
            message:'an error occured'
        });
    })
    
});

module.exports = {router};