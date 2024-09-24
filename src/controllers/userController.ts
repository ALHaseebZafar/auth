// src/controllers/userController.ts
import { Request, Response } from "express";
import User from "../models/user";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt"; // Make sure to import bcrypt
import OTP from "../models/otp"; // Adjust the path as needed
import crypto from "crypto";
import { transporter } from "../utils/emailService";
import dotenv from "dotenv";
dotenv.config();

// Function to generate authentication token
export const generateAuthToken = async (user: any) => {
  const secret = process.env.JWT_SECRET;

  if (!secret) {
    throw new Error("JWT_SECRET is not defined in environment variables");
  }

  const token = jwt.sign({ _id: user._id.toString() }, secret, {
    expiresIn: "1h",
  });

  user.tokens = user.tokens.concat({ token });
  await user.save();

  return token;
};

export const signup = async (req: Request, res: Response) => {
  const { firstname, lastname, cellno, email, password } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      firstname,
      lastname,
      email,
      password: hashedPassword,
      cellno,
    });

    await user.save();

    // Generate OTP and its expiration time
    const otp = crypto.randomInt(100000, 999999).toString();
    const expiresAt = Date.now() + 10 * 60 * 1000;

    // Create OTP entry
    const otpEntry = new OTP({ email, otp, expiresAt });
    await otpEntry.save();

    // Prepare email for sending OTP
    const resetUrl = `http://localhost:3000/verify-otp?otp=${otp}`;
    const mailOptions = {
      from: "noreply@example.com",
      to: email,
      subject: "Your OTP Code",
      text: `Your OTP code is ${otp}. It is valid for 10 minutes. Click the link to verify your email: ${resetUrl}`,
    };

    // Send the email
    await transporter.sendMail(mailOptions);

    // Respond to the client
    res
      .status(201)
      .send({ message: "User created and OTP sent to your email." });
  } catch (e: unknown) {
    res.status(400).send({ error: "Error creating user" });
  }
};

export const verifyotp = async (req: Request, res: Response) => {
  const { email, otp } = req.body;

  try {
    // Find the OTP entry in the database
    const otpEntry = await OTP.findOne({ email, otp });
    if (!otpEntry) {
      return res.status(400).send({ error: "Invalid OTP." });
    }

    // Check if the OTP has expired
    if (otpEntry.expiresAt.getTime() < Date.now()) {
      return res.status(400).send({ error: "OTP expired." });
    }

    // OTP is valid, delete the OTP entry
    await OTP.deleteOne({ _id: otpEntry._id });

    // Respond with a success message
    res.send({
      message: "OTP verified successfully. Please verify your email.",
    });
  } catch (e) {
    console.error("Error during OTP verification:", e);
    res.status(500).send({ error: "An error occurred while verifying OTP." });
  }
};


export const verifyemail = async (req: Request, res: Response) => {
  const { email } = req.body;

  try {
    // Find the user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).send({ error: "User not found." });
    }

    // Update user status to "verified"
    user.status = "verified";
    await user.save();

    // Respond with a success message
    res.send({
      message: "Email verified successfully. You can now log in.",
    });
  } catch (e) {
    console.error("Error during email verification:", e);
    res.status(500).send({ error: "An error occurred while verifying email." });
  }
};

export const login = async (req: Request, res: Response) => {
  const { email, password } = req.body;

  try {
    // Validate input
    if (!email || !password) {
      return res.status(400).send({ error: "Email and password are required" });
    }

    // Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).send({ error: "Invalid email or password" });
    }

    // Check if the user is verified
    if (user.status === "pending verification") {
      // Generate OTP and expiration time
      const otp = crypto.randomInt(100000, 999999).toString();
      const expiresAt = Date.now() + 10 * 60 * 1000;

      // Save OTP to the OTP collection
      const otpEntry = new OTP({ email, otp, expiresAt });
      await otpEntry.save();

      // Send OTP via email
      const mailOptions = {
        from: "noreply@example.com",
        to: email,
        subject: "Verify your account with OTP",
        text: `Your OTP code is ${otp}. It is valid for 10 minutes.`,
      };
      await transporter.sendMail(mailOptions);

      return res.status(401).send({
        error: "Email not verified. OTP sent to your email. Please verify.",
      });
    }

    // Check if the password is correct
    const isPasswordMatch = await bcrypt.compare(password, user.password);
    if (!isPasswordMatch) {
      return res.status(400).send({ error: "Invalid email or password" });
    }

    // Generate JWT token
    const token = jwt.sign(
      { _id: user._id.toString() },
      process.env.JWT_SECRET!,
      { expiresIn: "2h" }
    );

    // Send user and token back to the client
    res.status(200).send({
      message: "Login successful",
      user: {
        firstname: user.firstname,
        lastname: user.lastname,
        email: user.email,
      },
      token,
    });
  } catch (e: any) {
    console.log("Login error:", e.message);
    res.status(500).send({ error: "An error occurred during login" });
  }
};
export const findByCredentials = async (
  email: string,
  password: string
): Promise<any> => {
  try {
    // Log the email being searched for
    // console.log("Finding user with email:", email);

    const user = await User.findOne({ email });
    // console.log("User found:", user); // Check if user is found

    if (!user) {
      throw new Error("Unable to login - user not found");
    }

    // Compare the password using bcrypt
    const isMatch = await bcrypt.compare(password, user.password);
    console.log("Password match:", isMatch); // Log the result of password comparison

    if (!isMatch) {
      throw new Error("Unable to login - incorrect password");
    }

    return user;
  } catch (e: any) {
    console.log("Error in findByCredentials:", e.message);
    throw e;
  }
};

export const forgetpassword = async (req: Request, res: Response) => {
  try {
    const { email } = req.body;

    // Find the user by email
    const user = await User.findOne({ email });
    if (!user) {
      // Don't disclose whether the user exists for security reasons
      return res
        .status(404)
        .send({
          message:
            "If this email is registered, a password reset link will be sent.",
        });
    }

    // Generate a new reset token
    const resetToken = jwt.sign(
      { _id: user._id.toString() },
      process.env.JWT_SECRET!,
      {
        expiresIn: "1h",
      }
    );

    // Save the reset token with expiration time (optional)
    user.resetToken = resetToken;
    await user.save();

    // Create password reset URL
    const resetUrl = `http://localhost:3000/reset-password?token=${resetToken}`;
    const mailOptions = {
      from: "noreply@example.com",
      to: user.email,
      subject: "Password Reset Request",
      text: `You requested a password reset. Click the link to reset your password: ${resetUrl}`,
    };

    // Send the email
    await transporter.sendMail(mailOptions);

    // Respond with a success message
    res.send({
      message:
        "If this email is registered, a password reset link has been sent.",
    });
  } catch (e) {
    console.error("Error requesting password reset:", e);
    res
      .status(500)
      .send({ error: "An error occurred while requesting a password reset." });
  }
};

export const resetpassword = async (req: Request, res: Response) => {
  try {
    const { token, password } = req.body;

    // Validate input
    if (!token || !password) {
      return res.status(400).send("Token and new password are required.");
    }

    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
      return res.status(500).send("JWT secret is not configured.");
    }

    // Verify the token and get the decoded payload
    const decoded = jwt.verify(token, jwtSecret) as jwt.JwtPayload;

    // Find the user using the decoded _id
    const user = await User.findOne({ _id: decoded._id });

    if (!user) {
      return res.status(404).send("User not found.");
    }

    // Check if the reset token matches
    if (user.resetToken !== token) {
      return res.status(400).send("Invalid or expired token.");
    }

    // Hash the new password before saving
    user.password = await bcrypt.hash(password, 10);
    user.resetToken = undefined; // Clear the reset token after successful reset

    await user.save(); // Save the updated user

    res.send("Password reset successfully.");
  } catch (e: any) {
    console.error(e.message); // Log the error message for debugging
    res.status(500).send("An error occurred while resetting the password.");
  }
};
