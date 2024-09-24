import nodemailer from 'nodemailer'

// Looking to send emails in production? Check out our Email API/SMTP product!
export const transporter = nodemailer.createTransport({
    host: "sandbox.smtp.mailtrap.io",
    port: 2525,
    auth: {
      user: "3d4e0422152822",
      pass: "15684a69c59c23"
    }
  });
