const express = require('express');
const {User} = require('../models/user');
const router = express.Router();
const {checkSecret,checkUserLevel,checkAdmin,levelAccess} = require('../tools/toolExports');
const passport = require('passport');
const jwtAuth = passport.authenticate('jwt', { session: false });

router.post('/admin',checkSecret,checkAdmin,(req,res) => {
    const {email,password,level} = req.body;
    return User.hashPassword(password)

    .then(hash => {
        return User.create({
            email,
            password:hash,
            admin:true,
            level
        })
    })

    .then(user => {
        return res.json({
            code:200,
            message:'User created'
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

router.post('/user',jwtAuth,checkUserLevel,(req,res) => {
    const {email,password,level} = req.body;

    return User.hashPassword(password)

    .then(hash => {
        return User.create({
            email,
            password:hash,
            level
        })
    })

    .then(user => {
        return res.json({
            code:200,
            message:'User created'
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


router.get('/',jwtAuth,(req,res) => {

    return User.find({level:{$ne:null}})

    .then(users => {
        return res.json({
            code:200,
            users:users.map(user => user.serialize())
        });
    })

    .catch(err => {
        console.log('error ',err);

        return res.json({
            code:500,
            message:'an error occured'
        });
    })
    
});

router.put('/',async (req,res) => {
    const {email,password} = req.body;

    try {
        const users = await User.find({email});
        const user = users[0];
        
        if(user && !user.password){
            const hash = await User.hashPassword(password);
            const users = await User.findOneAndUpdate({ email }, {
                $set: { password: hash }
            });
            return res.json({
                code: 200,
                message:'updated password'
            });
        }
        else{
            return res.json({
                code: 400,
                message:'cannot update password'
            });
        }
        
    }
    catch (err) {
        console.log('error ', err);
        return res.json({
            code: 500,
            message: 'an error occured'
        });
    }
    
});
//update user
router.put('/:email',jwtAuth,levelAccess(0),async (req,res) => {
    const {email} = req.params;
    const {user} = req.body;

    try {
        const users = await User.findOneAndUpdate({ email }, {
            $set: user
        });
        res.status(200);
        return res.json({
            code: 200,
            message:'updated user'
        });
        
    }
    catch (err) {
        console.log('error ', err);
        res.status(500);
        return res.json({
            code: 500,
            message: 'an error occured'
        });
    }
    
});



router.put('/reset',checkSecret,jwtAuth,async (req,res) => {
    const {email} = req.body;

    try {
        const users = await User.findOneAndUpdate({ email }, {
            $set: { password: null }
        });
        return res.json({
            code: 200,
            message:'reset password'
        });
    }
    catch (err) {
        console.log('error ', err);
        return res.json({
            code: 500,
            message: 'an error occured'
        });
    }
    
});

module.exports = {router};