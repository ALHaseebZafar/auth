// src/app.ts or src/server.ts
import dotenv from 'dotenv';
dotenv.config();
import './db/mongoose'; // Connect to MongoDB

import express from 'express';
import authRouter from './routers/auth';

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());

app.use(authRouter);

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
