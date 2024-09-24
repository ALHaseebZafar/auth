import jwt from 'jsonwebtoken';
import User from '../models/user';
import { Request, Response, NextFunction } from 'express';

declare global {
    namespace Express {
      interface Request {
        user?: any; // Add user property of type any
      }
    }
  }
  



const auth = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');

    if (!token) {
      throw new Error('No token provided');
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET as string);
    const user = await User.findOne({ _id: (decoded as { _id: string })._id });

    if (!user) {
      throw new Error('User not found');
    }

    req.user = user; // Now TypeScript recognizes this
    next();
  } catch (e) {
    console.log('Error:', e);
    res.status(401).send("Please Authenticate");
  }
};

export default auth;
