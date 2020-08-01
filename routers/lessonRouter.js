const express = require('express');
const {Lesson} = require('../models/lesson');
const router = express.Router();
const passport = require('passport');
const {findById,findByEmail,generalSearch} = require('./tools/search');
const {totalHours,totalStudents,hourBreakdown} = require('./tools/hours');
//const {checkAdminEmails,checkEmail,checkUser,checkAdminLocs} = require('../tools/toolExports');
const jwtAuth = passport.authenticate('jwt', { session: false });
router.use(jwtAuth);

router.post('/',(req,res) => {
    const {date,lessonType,notes,students,teacher} = req.body;
    console.log(req.body);
    return Lesson.create({
        date,
        lessonType,
        notes,
        students,
        teacher
    })

    .then(lesson => {
        return res.json({
            code:200,
            message:'Lesson created'
        });
    })

    .catch(err => {
        console.log('error ',err);
        if(err.message.includes('E11000')){
            return res.json({
                code:401,
                message:'Lesson already exists'
            });
        }
        return res.json({
            code:500,
            message:'an error occured'
        });
    })
    
});

router.get('/',(req,res) => {
    return Lesson.find({}).populate('students').populate('teacher')

    .then(lessons => {
       return res.json({
            code:200,
            lessons:lessons.map(lesson => lesson.serialize())
        }); 
    })

    .catch(err => {
        return res.json({
            code:500,
            message:'an error occured',
            error:err
        });
    });
});

router.get('/my-lessons',(req,res) => {
    let {id,email,startDate,endDate} = req.query;
    let start = startDate ? new Date(startDate) : new Date();
    //inclusive of start day
    start.setDate(start.getDate() + 1);
    let end = endDate ? new Date(endDate) : new Date(start);
    if(!endDate){
        const defaultRange = 30;
        end.setDate(end.getDate() - 30);
    }
    //inclusive of end day
    end.setDate(end.getDate() - 1);
    start.setHours(0,0,0,0);
    end.setHours(0,0,0,0);
    console.log(id,email,findById);
    if(id){
        return findById(id,start,end)

        .then(lessons => {
            return res.json({
                code:200,
                lessons:lessons.map(lesson => lesson.serialize())
            }); 
        })
        .catch(err => {
            return res.json({
                code:500,
                message:'an error occured',
                error:err
            });
        });
    }
    else if(email){
        return findByEmail(email,start,end)

        .then(lessons => {

            return res.json({
                code:200,
                lessons:lessons.map(lesson => lesson.serialize())
            }); 
        })
        .catch(err => {
            return res.json({
                code:500,
                message:'an error occured',
                error:err
            });
        });
    }
    
});

function createUpdateData(body){
    let data = {};
    let today = new Date();
    for(let field in body){
        data[field] = body[field];
    }
    //pass from browser?
    data.lastEdited = data.lastEdited ? data.lastEdited : today;

    return data;
}

router.put('/:id',(req,res) => {
    let {id} = req.params;
    const updateData = createUpdateData(req.body);

    return Lesson.findOneAndUpdate({'_id':id},{
        $set:updateData,
        $inc:{"totalEdits":1}
    },{
        useFindAndModify:false
    })

    .then(response => {
        return res.json({
            code:200,
            message:'Lesson Updated'
        });
    })

    .catch( err=> {
        console.log('Error updating lesson ',err);
        return res.json({
            code:500,
            message:'Error Updating lesson',
            error:err.errmsg
        });
    });
});

router.get('/summary',(req,res) => {
    let {id,email,startDate,endDate} = req.query;
    let start = startDate ? new Date(startDate) : new Date();
    //inclusive of start day
    start.setDate(start.getDate() + 1);
    let end = endDate ? new Date(endDate) : new Date(start);
    if(!endDate){
        const defaultRange = 30;
        end.setDate(end.getDate() - 30);
    }
    //inclusive of end day
    end.setDate(end.getDate() - 1);
    start.setHours(0,0,0,0);
    end.setHours(0,0,0,0);
    console.log(id,email,findById);
    if(id){
        return findById(id,start,end)

        .then(lessons => {
            let lessonData = {};
            let serializedLessons = lessons.map(lesson => lesson.serialize());
            lessonData.totalHours = totalHours(serializedLessons);
            lessonData.totalStudents = totalStudents(serializedLessons);
            lessonData.hours = hourBreakdown(serializedLessons);
            return res.json({
                code:200,
                lessonData
            }); 
        })
        .catch(err => {
            return res.json({
                code:500,
                message:'an error occured',
                error:err
            });
        });
    }
    else if(email){
        return findByEmail(email,start,end)

        .then(lessons => {
            let lessonData = {};
            let serializedLessons = lessons.map(lesson => lesson.serialize());
            lessonData.totalHours = totalHours(serializedLessons);
            lessonData.totalStudents = totalStudents(serializedLessons);
            lessonData.hours = hourBreakdown(serializedLessons);
            return res.json({
                code:200,
                lessonData
            }); 
        })
        .catch(err => {
            return res.json({
                code:500,
                message:'an error occured',
                error:err
            });
        });
    }
    
});

module.exports = {router};