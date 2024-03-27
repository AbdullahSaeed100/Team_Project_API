const express=require('express');
const router =express.Router();
const Errors= require('../util/Errors');

const authController=require('../controllers/authController');
const userController=require('../controllers/userController');

router.post('/signup',authController.signup);
router.post('/login',authController.login);
router.post('/forgetPassword',authController.forgetPassword);
router.post('/resetPassword/:token',authController.resetPassword);


router.get('/:id',authController.protect,authController.restrictTo('admin'),userController.getById);
router.all('*',(req,res,next)=>{
    next(new Errors(`can't find ${req.originalUrl} on server`,404));
});

module.exports=router;