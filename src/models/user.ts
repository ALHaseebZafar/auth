import mongoose from "mongoose";
import validator from "validator";

const userSchema = new mongoose.Schema({
  firstname: {
    type: String,
    required: true,
    trim: true,
  },
  lastname: {
    type: String,
    required: true,
    trim: true,
  },
  cellno: {
    type: String, // Changed from Number to String
    required: true,
    trim: true,
  },
  email: {
    type: String,
    unique: true,
    required: true,
    lowercase: true,
    trim: true,
    validate(value: string) {
      if (!validator.isEmail(value)) {
        throw new Error("Email is invalid");
      }
    },
  },
  password: {
    type: String,
    required: true,
    minlength: 7,
    trim: true,
    validate(value: string) {
      if (value.toLowerCase().includes("password")) {
        throw new Error('Password cannot contain "password"');
      }
    },
  },
  status: {
    type: String,
    enum: ["pending verification", "verified"], // Added enum for consistency
    default: "pending verification",
  },
  tokens: [
    {
      token: {
        type: String,
        required: true,
      },
    },
  ],
  resetToken: String,
  otp: String, // Use String if you plan to hash the OTP
  otpExpires: Date,
});

const User = mongoose.model("User", userSchema);
export default User;
