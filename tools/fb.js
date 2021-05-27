const admin = require('firebase-admin');
const {User} = require('../models/user');

const checkFbAuth = async(req,res,next) => {
    if(req.headers.authtoken){
        try{
            const decodedToken = await admin.auth().verifyIdToken(req.headers.authtoken);
            let {email,name} = decodedToken;
            
            let user = await User.findByEmail(email);
            if(!user){
                let userData = {
                    email,
                    level:0
                };
                if(name){
                    let splitName = name.split(' ');
                    userData.firstName = splitName[0];
                    userData.lastName = splitName[1];
                }
                console.log('new user: ',userData)
                user = await User.create(userData);
                throw {
                    message:'new user'
                };
            }
            else{
                if(user.level || user.level === 0){
                    req.user = user;
                }
                else{
                    throw {
                        message:'new user'
                    };
                }
            }
            next();
        }
        catch(e){
            res.status(421);
            return res.json({
                message:'Unauthorized'
            });
        }
    }
    else{
        res.status(422);
        return res.json({
			message:'Unauthorized'
		});
    }
}

module.exports = {checkFbAuth};