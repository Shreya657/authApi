import { asyncHandler } from "../utils/asyncHandler.js";
import mongoose from "mongoose";
import {ApiError} from "../utils/ApiError.js"
import {User} from "../models/user.model.js"
import { ApiResponse } from "../utils/ApiResponse.js";
import { response } from "express";
import jwt from "jsonwebtoken"
import validator from "validator"
import { sendEmail } from "../utils/sendEmail.js";
import crypto from "crypto"
import { OAuth2Client } from "google-auth-library";

const client=new OAuth2Client(process.env.GOOGLE_CLIENT_ID)

//This creates a Google OAuth2 client which helps your backend verify the idToken sent by the frontend.



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
    const { email,username,password,redirectUrl}=req.body
    console.log("email: ",email);
     
    if(
        [email,username,password,redirectUrl].some((field)=>field?.trim()==="")
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

 

     const user = await User.create({
    email,
    password,
    username: username.toLowerCase(),
    isEmailVerified:false
  });
 const verificationToken=user.generateVerificationToken();
 await user.save({validateBeforeSave:false});
  const verificationURL=`${redirectUrl}/verify-email/${verificationToken}`
  const message = `Click the following link to verify your email:\n\n${verificationURL}`;
  await sendEmail(user.email, "Verify your email", message);


    const createdUser=await User.findById(user._id).select("-password -refreshToken")

    if(!createdUser){
        throw new ApiError(500,"something went wrong while registering")
    }
const {accessToken,refreshToken}=await generateAccessAndRefreshTokens(user._id)


  // ✅ Save refreshToken in DB
  user.refreshToken = refreshToken;
  await user.save({ validateBeforeSave: false });
  const options={
    httpOnly:true,
    secure:true
}
    return res
    .status(200)
    .cookie("accessToken",accessToken,options)
.cookie("refreshToken",refreshToken,options)
    .json(new ApiResponse(200,  {
        user: createdUser,
        accessToken,
        refreshToken,
      },
      "Registration successful."
    ))

})



 const verifyEmail = asyncHandler(async (req, res) => {
  const { token } = req.query;

  if (!token) {
    throw new ApiError(400, "Verification token is missing");
  }

  const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

  const user = await User.findOne({
     
    emailVerificationToken: hashedToken,
    emailVerificationExpiry: { $gt: Date.now() }, // token not expired
  });
    console.log("hashed: ",hashedToken)
    console.log("User found:", user);
  if (!user) {
    throw new ApiError(400, "Token is invalid or expired");
  }

  user.isEmailVerified = true;
  user.emailVerificationToken = undefined;
  user.emailVerificationExpiry = undefined;

  await user.save({ validateBeforeSave: false });

  return res
    .status(200)
    .json(new ApiResponse(200, {}, "Email verified successfully ✅"));
});





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
 if (!user.isEmailVerified) {
    throw new ApiError(401, "Please verify your email before logging in");
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

const refreshAccessToken=asyncHandler(async(req,res)=>{
const incomingRefreshToken= req.cookies.refreshToken || req.body.refreshToken;  
 //✅ Looks for refreshToken:
// First in cookies
// If not found, tries from req.body (good fallback)
if(!incomingRefreshToken)
{
  throw new ApiError(401,"unauthorized request");
}
try {

  //🔐 Decode and verify the refresh token.
// If token is invalid or expired, it throws → handled in catch
    const decodedToken= jwt.verify(
    incomingRefreshToken,
    process.env.REFRESH_TOKEN_SECRET
  )
  

  //🔍 Find the user from DB using ID from token payload
  const user= await User.findById(decodedToken?._id)
  
  if(!user){
      throw new ApiError(401,"invalid refresh token");
  
  }
  //🔒 Make sure the refresh token from client matches the one stored in DB
  if(incomingRefreshToken!==user?.refreshToken){
        throw new ApiError(401,"refresh token is expired or used");
  
  }
  
  //⚠️ Protects against token reuse or stolen token
  const options={
    httpOnly:true,
    secure: true
  }
  
  const {accessToken,refreshToken:newRefreshToken}= await generateAccessAndRefreshTokens(user._id);
  
  return res
  .status(200)
  .cookie("accessToken",accessToken,options)
  .cookie("refreshToken",newRefreshToken,options)
  .json(
    new ApiResponse(
      200,
      {accessToken,refreshToken: newRefreshToken},
      "access token refreshed"
    )
  )
  
} catch (error) {
    throw new ApiError(401,error?.message || "invalid refresh token")
  
}




})




const changeCurrentPassword=asyncHandler(async(req,res)=>{
  const {oldPassword,newPassword,confirmPassword}=req.body

  if(newPassword!==confirmPassword){
    throw new ApiError(400,"password doesnt match")
  }
  if (newPassword.length < 6) {
    throw new ApiError(400, "Password must be at least 6 characters long");
}

 const user= await User.findById(req.user?._id)
 console.log("req.user:", req.user);

if(!user){
  throw new ApiError(404,"user not found");
}
 const isPasswordCorrect= await user.isPasswordCorrect(oldPassword)

 if(!isPasswordCorrect){
  throw new ApiError(400,"invalid old password")
 }

 user.password=newPassword
 await user.save({validateBeforeSave:false})

 return res
 .status(200)
 .json(new ApiResponse(200,{},"password changed successfully"))
})

const getCurrentUser=asyncHandler(async(req,res)=>{
   const user = await User.findById(req.user._id);
  return res
  .status(200)
  .json(new ApiResponse(200,user,"current user fetched successful"));
})


const updateAccountDetails=asyncHandler(async(req,res)=>{

  const {username,email}=req.body

   if(!validator.isEmail(email)){
        throw new ApiError(400,"provide a valid email")
    }

  const ExistingEmail=await User.findOne({email});
  if(!ExistingEmail&& ExistingEmail._id.toString()==req.user._id.toString()){
    throw new ApiError(409, "Email is already in use by another account");
  }

  if(!username || !email){
    throw new ApiError(400,"username or email required")
  }

  const user= await User.findByIdAndUpdate(req.user?._id,
    {
      $set:{
        username:username,
        email:email
      }

    },
    {new:true}
  ).select("-password")

  return res
  .status(200)
  .json(new ApiResponse(200,user,"Account details updated successfully"))
})



const forgotPassword=asyncHandler(async(req,res)=>{
  const {email,redirectUrl}=req.body;
  if(!email || !redirectUrl){
    throw new ApiError(400,"email is required");
  }

  const user=await User.findOne({email});

  console.log("Email received:", email);

   if (!user) {
    throw new ApiError(404, "User not found");
  }

  const resetToken=user.generatePasswordResetToken()
  await user.save({validateBeforeSave:false});
  console.log("Saved user:", await User.findById(user._id));
  const resetURL=`${redirectUrl}/reset-password/${resetToken}`;
    console.log(`🔗 Password reset link (for dev only): ${resetURL}`);


    
const message = `
  <h2>Password Reset Request</h2>
  <p>Click the link below to reset your password. This link will expire in 15 minutes.</p>
  <a href="${resetURL}" target="_blank">${resetURL}</a>
`;

await sendEmail(user.email, "Reset Your Password", message);

    return res
    .status(200)
    .json(new ApiResponse(200,{},"reset link sent to email"))
})


const resetPassword=asyncHandler(async(req,res)=>{
  const {token}=req.params;
  const{newPassword,confirmPassword}=req.body;
  if (newPassword !== confirmPassword) {
    throw new ApiError(400, "Passwords do not match");
  }

   const hashedToken = crypto.createHash("sha256").update(token).digest("hex");
     const user = await User.findOne({
    resetPasswordToken: hashedToken,
    resetPasswordExpiry: { $gt: Date.now() },  //Find users whose resetPasswordExpiry time is greater than the current time (i.e., not expired yet)."
  });

 console.log("user: ",user);

  if (!user) {
    throw new ApiError(400, "Invalid or expired reset token");
  }

    user.password = newPassword;
  user.resetPasswordToken = undefined;
  user.resetPasswordExpiry = undefined;
  await user.save({ validateBeforeSave: false });

    return res.status(200).json(
    new ApiResponse(200, {}, "Password has been reset successfully")
  );

})




const deleteAccount=asyncHandler(async(req,res)=>{
  const userId=req.user._id;  //id is a string not an obj
  const user=await User.findById(userId);
  if(!user){
    throw new ApiError(404,"user not found");
  }

  const ans= await User.findByIdAndDelete(userId)
  // console.log("deleted: ",ans);
    res.clearCookie("accessToken");
  res.clearCookie("refreshToken");


  return res
  .status(200)
  .json(new ApiResponse(200,{},"account has been deleted successfully from database"))


})


const msg=asyncHandler(async(req,res)=>{
  return res
  .status(200)
  .json(new ApiResponse(200,{status: "UGMI"},"Im living for a thrillll......formula🫶"))
})



const googleOAuth=asyncHandler(async(req,res)=>{
//  👇 Extracting the token sent from frontend (Google gives this after successful login)
    const { idToken } = req.body;
  if(!idToken){
    throw new ApiError(400,"id token is required")
  }

  //   // ✅ Verifying that the token is real and was issued for your app
const ticket=await client.verifyIdToken({idToken,
  audience:process.env.GOOGLE_CLIENT_ID
});

const payload=ticket.getPayload(); // This extracts the user info from the token:
const{email,name,picture,sub}=payload
if(!email){
      throw new ApiError(400,"email not found in token")

}

let user=await User.findOne({email});  //Check if this user already exists in your MongoDB.
if(!user){  //if user not exist in db----do register them
      user=await User.create({
        username:name|| "no name",
        email,
        password:sub,        //  using Google's user ID (sub) as a placeholder password
        isGoogleAccount:true  //marking this user as signed up via Google
      });

      // sub stands for subject — a unique ID Google assigns to every user.
      //It’s not a password but works as a unique identifier.
      //We use it only as a dummy password placeholder because your model requires one.

}
if (!user.isGoogleAcc) {
  user.isGoogleAcc = true;
  await user.save();
}
// // ✅ Generate access + refresh tokens
const {accessToken,refreshToken}=generateAccessAndRefreshTokens(user._id);
const userData=user.toObject();

//   ✅ Send success response
return res
.status(200)
.json(new ApiResponse(200,{user: userData,accessToken,refreshToken},"logged in successfully via google"))
  
})







export {registerUser,loginUser,logoutUser,forgotPassword,resetPassword,getCurrentUser,refreshAccessToken,changeCurrentPassword,updateAccountDetails,deleteAccount,msg,googleOAuth,verifyEmail}