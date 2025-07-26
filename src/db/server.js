import mongoose from "mongoose"
import { DB_NAME } from "../constants.js"

const connectDB=async()=>{
    try{
       const connectionInstance=await mongoose.connect(`${process.env.MONGODB_URL}/${DB_NAME}`) 
       console.log(`\nkoi na..MongoDb tere sath hai😋`)

    }catch(error){
        console.log("MongoDB nhi hai vai kya kar rha hai tu BKL?!!",error)
        process.exit(1)
    }

   
}

 export default connectDB