import dotenv from "dotenv"
import mongoose from "mongoose"
import { DB_NAME } from "./src/constants.js"; 
import connectDB from "./src/db/server.js";
import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import { app } from "./src/app.js";


dotenv.config({
    path:'./.env'
})
connectDB()

.then(()=>{
    app.listen(process.env.PORT||3000,()=>{
        console.log(`Server is running on port ${process.env.PORT}`);
        
    });
})         

.catch((err)=>{
    console.log("MONGODB CONNECTION FAILED!!!",err);

})
