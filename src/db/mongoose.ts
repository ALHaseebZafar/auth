import mongoose from 'mongoose'
import dotenv from 'dotenv'
dotenv.config();


const mongoURI= process.env.MONGO_URI;

if (!mongoURI) {
    throw new Error('MONGO_URI is not defined in environment variables');
  }
  

mongoose
  .connect(mongoURI)
  .then(() => {
    console.log("Database connected successfully");
  })
  .catch((err) => {
    console.error("Database connection error:", err);
  });
