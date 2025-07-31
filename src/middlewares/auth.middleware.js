import { User } from "../models/user.model.js";
import { ApiError } from "../utils/ApiError.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import jwt from "jsonwebtoken"

export const verifyJWT= asyncHandler(async(req, _,next)=>{
try {

    // 🔐 Token sources checked in this order:
    // *  1. Cookie: 'accessToken'
    // *  2. Header: 'Authorization: Bearer <token>'
    // const token= req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ","")
    const token = req.header("Authorization")?.replace("Bearer ", "") || req.cookies?.accessToken;

    if(!token){
        throw new ApiError(401,"unauthorized request");
    }

    //	Verify the token using jwt.verify()
    const decodedToken= jwt.verify(token,process.env.ACCESS_TOKEN_SECRET)
    

    //Fetch the user using the ID from token & Remove sensitive fields (password, refreshToken)
    const user= await User.findById(decodedToken?._id).select("-password -refreshToken")
    
    if(!user){
    
        throw new ApiError(401,"invalid access token");
    }
    

    //attach user to request
    req.user=user;

    // move to next middleware or controller
    next()
} catch (error) {
    throw new ApiError(401,error?.message || "Invalid access token")
}





})