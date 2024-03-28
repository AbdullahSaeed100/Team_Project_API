const crypto=require('crypto');
const mongoose = require('mongoose');
const validator=require('validator');
const bcrypt = require('bcryptjs');
//Schema
const userSchema =new mongoose.Schema({
    name:{
        type: String,
        required: [false,'title must be specified'],
        trim: true,
        maxlength: [50, 'User name must be less than or equal 50'],
        minlength: [7, 'User name must be more than or equal 7'],
        validate:{ 
        validator: function(name){
                    const regex=/^[A-Za-z ]*$/;
                    return regex.test(name);
                    },
        message: "name must consist of Letters and spaces only"
        }
            
    },
    email:{
        type: String,
        trim: true,
        required: [true,'email must be entered'],
        validate: [validator.isEmail, 'email must be in right format'],
        unique: true,//? add 
        //maxlength: [45, 'email must be less than or equal 49'],
        //minlength: [10, 'email must be more than or equal 10']
            
    },
    role: {
        type: String,
        enum: ['user','admin'],
        default: 'user'
    },
    password:{
        type: String,
            required: [true,'password must be entered'],
            trim: true,
            
            maxlength: [30, 'Password must be less than or equal 30'],
            minlength: [8, 'Password must be more than or equal 8'],
            validate:{ 
                validator: function(pass){
                            const regex=/(?=.*[a-zA-Z])(?=.*[0-9])(?=.*[!@#$%^])[a-zA-z0-9!@#$%^]{8,}/;
                            return regex.test(pass);
                            },
                message: "password must contain at least one letter, one digit and one of these !@#$%^"
            },
            
    },
    passwordChangeAt: Date,
    passwordResetToken: String,
    passwordResetExpiresIn: Date

    /*confirmPassword:{
        type: String,
        required: [true,'confirmPassword must be entered'],
        trim: true,
        validate:{
            validator: function(element){
                // this pnly works on save or create
                return element === this.password;
            },
            message:"confirm password must be the same as password"
        }
        
            
    }*/
})

userSchema.pre('save',async function (next){
    //run only if the password modified
    if(!this.isModified('password')) return next();
    //hash the password with 12 fields
    this.password= await bcrypt.hash(this.password,12);
    //no need for confirm password anymore
    //this.confirmPassword=undefined;
});
userSchema.pre('save',function (next){
    if(!this.isModified('password') || this.isNew)return next();
    this.passwordChangeAt=Date.now()-1000;
    next();
})
userSchema.methods.correctPassword= async function (enteredPassword,realPassword){
    return await bcrypt.compare(enteredPassword,realPassword);
}
userSchema.methods.changePasswordAfter=async function(JWTTime){
    if(this.passwordChangeAt){
        
        const changedPassordChangedAt=parseInt(this.passwordChangeAt.getTime()/1000, 10);
        return changedPassordChangedAt > JWTTime;

    }
    //user did not change password
    return false;
}
userSchema.methods.generatePasswordResetToken= function(){
    const token=crypto.randomBytes(32).toString('hex');
    
    this.passwordResetToken=crypto.createHash('sha256').update(token).digest('hex');

    this.passwordResetExpiresIn=Date.now()+10*60*1000;
    console.log({token},this.passwordResetToken,this.passwordResetExpiresIn);
    return token;
}

const userModel = mongoose.model('user',userSchema);
module.exports=userModel;