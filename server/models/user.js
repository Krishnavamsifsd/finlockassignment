import mongoose from "mongoose";

const userSchema = mongoose.Schema({
  email:String,
  password:String
})

export default mongoose.model("users",userSchema)