import mongoose, { Schema } from 'mongoose';

const otpSchema = new Schema({
  email: {
    type: String,
    required: true,
    lowercase: true,
    trim: true,
  },
  otp: {
    type: String,
    required: true,
  },
  expiresAt: {
    type: Date,
    required: true,
  },
});

// Create and export the OTP model
const OTP = mongoose.model('OTP', otpSchema);

export default OTP;
