const crypto=require('crypto');
const { promisify }=require('util');
const userModel=require('../models/User');
const Errors = require('../util/Errors');
const catchAsync=require('../util/catchAsync')
const jwt= require('jsonwebtoken');
const sendEmail=require('../util/email');

const generateToken= (userId,userEmail)=>{
    return jwt.sign({id: userId,email: userEmail},process.env.JWT_SECRET,{expiresIn: process.env.JWT_EXPIRES_IN});
}

exports.signup= catchAsync(async (req,res,next)=>{
    const userEmail=req.body.email;
    const user = await userModel.findOne({ 'email':userEmail });
    
    if(user) 
        return next(new Errors(`The email ${userEmail} is already existed`,409))
        

    const newUser= await userModel.create({
        email: userEmail,
        password: req.body.password,
        role: req.body.role
    });
        //?await

    
    const token=generateToken(newUser._id,newUser.email);


    res.status(201).json({
        token
    })
    
})


exports.login= catchAsync(async (req,res,next)=>{
    
    const {email,password}=req.body;
    if(!email || !password)
        return next(new Errors('Missing input. Please provide email and password',400));

    
        const user = await userModel.findOne({ 'email':email });
    
        
        if(!user || !await user.correctPassword(password,user['password'])){
            return next(new Errors('Incorrect email or password.',401));
        }
    
    const token=generateToken(user._id,user.email);

    res.status(201).json({
        token
    })
    
})

exports.protect=catchAsync(async (req,res,next)=>{
    
    //1 get the token and check if it sent by client
    let token;
    if(req.headers.authorization && req.headers.authorization.startsWith('Bearer'))
        token =req.headers.authorization.split(' ')[1];
    
    if(!token)
        return next(new Errors(`You did not log in. Log in and try again.`,401));
    
    //2 verify token
    const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);
    
    //3 check if the user holding this token is exist or not
    const user=await userModel.findById(decoded.id);
    if(!user)
        return next(new Errors('the user ,who holds this token, does not exist',401))

    //4 check if the user changed password after token was created
    if(await user.changePasswordAfter(decoded.iat)){
        
        return next(new Errors('User changed password recently. please login again.',401));
    }

    //request passed all four tests 
    req.user=user;
    next();
})

exports.restrictTo = (...roles)=>{
    return (req,res,next)=>{
        if(!roles.includes(req.user.role)){
            return next(new Errors('You do not have premission to do this action',401));
        }
        next();
    }
    
}

exports.forgetPassword = catchAsync(async(req,res,next)=>{
    // get the user
    const user= await userModel.findOne({email:req.body.email});
    if(!user)
        return next(new Errors('there is no user with this email.',404));
    // generate random token
    const resetToken=user.generatePasswordResetToken();
    await user.save({validateBeforeSave:false});
    //send the random token to user
    const resetURL = `${req.protocol}://${req.get('host')}/users/resetPassword/${resetToken}`;

    const message=`Did you forget your password?click the following link to reset your password:\n${resetURL} \nif you didn't please ignore this email`;

try{
    await sendEmail({
        email: user.email,
        subject: '8Bit reset your password (valid for 10 min)',
        message
    })
    res.status(200).json({
        message: 'Token sent to email'
    })
}catch(err){
    user.passwordResetToken=undefined;
    user.passwordResetExpiresIn=undefined;
    await user.save({validateBeforeSave:false});
    next(new Errors('Error occured when sending email to reset password',500));
    
}
})
exports.resetPassword = catchAsync(async(req,res,next)=>{
    //1 getting user by token
    const hashedUser=crypto.createHash('Sha256').update(req.params.token).digest('hex');

    const user= await userModel.findOne({passwordResetToken:hashedUser,passwordResetExpiresIn:{$gt:Date.now()}});

    //2 set new password if the token is correct and did not expire
    if(!user){
        return next(new Errors('user token is not correct or has expired.'))
    }

    user.password=req.body.password;
    user.passwordResetToken=undefined;
    user.passwordResetExpiresIn=undefined;
    await user.save();

    //3 update changePasswordAt this is done in userSchema.pre('save' function) in user model.

    //4 log user in , generate token and send it
    const token=generateToken(user._id,user.email);

    res.status(201).json({
        token
    })

})

