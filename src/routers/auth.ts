import { Router, Request, Response } from "express";
import dotenv from "dotenv";

import { signup, verifyotp,verifyemail,login, forgetpassword, resetpassword } from "../controllers/userController";
dotenv.config();

const router = Router(); // Correctly initialize the router

router.post('/api/signup', signup);

router.post('/api/verify-email',verifyemail)
router.post("/api/verify-otp",verifyotp)

router.post("/api/login",login)

router.post('/api/forget-password',forgetpassword)

router.post('/api/reset-password',resetpassword)

export default router;
