const userModel = require('../models/User');
const catchAsync = require('../util/catchAsync');
const Errors = require('../util/Errors');


exports.getById=catchAsync(async (req,res,next)=>{
    const user= await userModel.findById(req.params.id);
    if(!user)
        return next(new Errors(`User wit id ${req.params.id} is not found.`,400));

        res.status(200).json(user);
});

exports.deleteUser=catchAsync(async (req,res,next)=>{
    await universityModel.findByIdAndDelete(req.params.id);
    return res.json({ 'message': 'universityModel deleted successfully' });
    
});