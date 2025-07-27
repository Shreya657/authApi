import { request } from "express"
import mongoose, { Schema } from "mongoose"
import jwt from "jsonwebtoken"
import bcrypt from "bcryptjs"
import crypto from "crypto"
import { boolean } from "webidl-conversions"
   


const userSchema=new Schema({
    username:{
        type:String,
        required:true,
        lowercase:true,
        unique:true,
        index:true,
        trim:true
    },
    email:{
        type:String,
        required:true,
        lowercase:true,
        unique:true,
        trim:true
    },
   
    password:{
        type:String,
        required:[true,'password is required']
    },
    refreshToken:{
        type:String
    },
    
    resetPasswordToken:{
        type:String
    },
    
   resetPasswordExpiry: { 
    type:Date
    },
    // emailVerificationToken:{
    //     type:String
    // },
    // emailVerificationExpiry:{
    //     type:Date
    // },
    // isEmailVerified:{
    //     type:Boolean,
    //     default:false
    // }

},{timestamps:true})

userSchema.pre("save",async function (next) {
    if(!this.isModified("password")){
        return next();
    }

    this.password=await bcrypt.hash(this.password,10)
    next();
})
userSchema.methods.isPasswordCorrect=async function(password) {
    return await bcrypt.compare(password,this.password);
}

userSchema.methods.generateAccessToken=function () {
    return jwt.sign(
        {
            _id:this._id,
            email:this.email,
            username:this.username,
            
        },
        process.env.ACCESS_TOKEN_SECRET,
        {
            expiresIn:process.env.ACCESS_TOKEN_EXPIRY
        }
    )
}

userSchema.methods.generateRefreshToken=function () {
    return jwt.sign(
        {
            _id:this._id,
        },
        process.env.REFRESH_TOKEN_SECRET,
        {
            expiresIn:process.env.REFRESH_TOKEN_EXPIRY
        }
    )
}



userSchema.methods.generatePasswordResetToken=function(){
    const resetToken=crypto.randomBytes(32).toString("hex");
    const hashedToken=crypto.createHash("sha256").update(resetToken).digest("hex");

    this.resetPasswordToken=hashedToken;
    this.resetPasswordExpiry=Date.now()+24*60*60*1000;  // 24 hrs

    return resetToken;
}

// userSchema.methods.generateVerificationToken=function(){
//     const verificationToken=crypto.randomBytes(32).toString("hex");
//     const emailHashedToken=crypto.createHash("sha256").update(verificationToken).digest("hex");

//     this.emailVerificationToken=emailHashedToken;
//     this.emailVerificationExpiry=Date.now()+24*60*60*1000;  // 24 hrs

//     return verificationToken;
// }




export const User=mongoose.model("User",userSchema);