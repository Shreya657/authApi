import { asyncHandler } from "../utils/asyncHandler.js";
import mongoose from "mongoose";
import {ApiError} from "../utils/ApiError.js"
import {User} from "../models/user.model.js"
import { ApiResponse } from "../utils/ApiResponse.js";
import { response } from "express";
import jwt from "jsonwebtoken"
import validator from "validator"




const generateAccessAndRefreshTokens = async(userId)=>{
  try{
    const user= await User.findById(userId); //fetch user from db by id
    const accessToken= user.generateAccessToken()  //generate short-lived tokens,generally for 15 mins..   //they are methods to find user id from User
    const refreshToken= user.generateRefreshToken()//generate long lived refresh token

    user.refreshToken=refreshToken //saving refresh token in db and keeping a reference to user
    await user.save({validateBeforeSave: false })  // ✅ Save updated user without running validation checks

    return {accessToken,refreshToken}

  }catch(error){
    throw new ApiError(500,"something went wrong while generating refresh and access token")
  }
}



const registerUser=asyncHandler(async(req,res)=>{
    const { email,username,password}=req.body
    console.log("email: ",email);
     
    if(
        [email,username,password].some((field)=>field?.trim()==="")
    ){
        throw new ApiError(400,"all fields are required");
    }

    if(!validator.isEmail(email)){
        throw new ApiError(400,"provide a valid email")
    }

    const existedUser=await User.findOne({
        $or:[{username},{email}]
    })

    if(existedUser){
     throw new ApiError(409,"User with email or username already exist")

    }

    const userObj=await User.create({
        email,
        password,
        username:username.toLowerCase()
    })

    const createdUser=await User.findById(userObj._id).select("-password -refreshToken")

    if(!createdUser){
        throw new ApiError(500,"something went wrong while registering")
    }

    return res
    .status(200)
    .json(new ApiResponse(200,createdUser,"successfully registered"))

})



const loginUser=asyncHandler(async(req,res)=>{
    const {email,username,password}=req.body

    if((!username && !email) ||!password){
        throw new ApiError(400,"username or email & password is required")
    }

    const user=await User.findOne({
        $or:[{username},{email}]
    })

    if(!user){
  throw new ApiError(404,"user not found");
}

const isPasswordValid=await user.isPasswordCorrect(password);
if(!isPasswordValid){
     throw new ApiError(401,"invalid user credentials");
 
}

const {accessToken,refreshToken}=await generateAccessAndRefreshTokens(user._id)

const loggedInUser=await User.findById(user._id).select("-password -refreshToken")

const options={
    httpOnly:true,
    secure:true
}


return res
.status(200)
.cookie("accessToken",accessToken,options)
.cookie("refreshToken",refreshToken,options)
.json(new ApiResponse(200,{user:loggedInUser,accessToken,refreshToken},"logged in successfully"))
})


const logoutUser=asyncHandler(async(req,res)=>{
 await User.findByIdAndUpdate(//findbyId: read the doc and returns if found but findbyidandupdates used for updates which save changes in db
  req.user._id, //using auth middleware to fetch user._id from token verification
  {
    $set: {
      refreshToken: undefined   // 🔄 Remove the stored refresh token in DB
    }
  },
  {
    new: true    //If { new: true } is passed, it returns the updated document
   // (without it, it returns the old document before update)
    
    
  }
 )

 const options={
  httpOnly:true,
  secure: true
}
return res
.status(200)
.clearCookie("accessToken",options)
.clearCookie("refreshToken",options)
.json(new ApiResponse(200,{},"User logged out"))

})





export {registerUser,loginUser,logoutUser}