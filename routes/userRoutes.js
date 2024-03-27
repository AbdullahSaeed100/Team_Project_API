const express=require('express');
const router =express.Router();
const Errors= require('../util/Errors');

const authController=require('../controllers/authController');
const userController=require('../controllers/userController');

router.post('/signup',authController.signup);
router.post('/login',authController.login);


router.get('/users/:id',authController.protect,userController.getById);
router.all('*',(req,res,next)=>{
    next(new Errors(`can't find ${req.originalUrl} on server`,404));
});

module.exports=router;