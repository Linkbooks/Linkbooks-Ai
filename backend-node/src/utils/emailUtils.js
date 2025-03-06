const nodemailer = require("nodemailer");
const config = require("../config/env");
const logger = require("./loggingUtils"); // ✅ Logging Utility

// ✅ Configure Nodemailer Transport
const transporter = nodemailer.createTransport({
  host: process.env.MAIL_SERVER || "smtp.gmail.com",
  port: process.env.MAIL_PORT || 587,
  secure: process.env.MAIL_USE_TLS === "True",
  auth: {
    user: process.env.MAIL_USERNAME,
    pass: process.env.MAIL_PASSWORD,
  },
});

/**
 * Sends a verification email with a unique token.
 * @param {string} email - User's email address.
 * @param {string} token - Unique verification token.
 */
const sendVerificationEmail = async (email, token) => {
  try {
    const verificationLink = `https://linkbooksai.com/verify-email?token=${token}`;

    const mailOptions = {
      from: process.env.MAIL_DEFAULT_SENDER || "no-reply@linkbooksai.com",
      to: email,
      subject: "Verify Your Email Address",
      html: `
        <html>
          <body>
            <p>Hello,</p>
            <p>Thank you for subscribing to LinkBooksAI!</p>
            <p>Please verify your email address by clicking the link below:</p>
            <p><a href="${verificationLink}" style="color: blue; font-weight: bold;">Verify Email</a></p>
            <p>This link will expire in 24 hours.</p>
            <p>If you did not subscribe, please ignore this email.</p>
          </body>
        </html>
      `,
    };

    await transporter.sendMail(mailOptions);
    logger.info(`✅ Verification email sent to ${email}`);
  } catch (error) {
    logger.error(`❌ Failed to send email to ${email}: ${error.message}`);
    throw new Error("Email sending failed.");
  }
};

module.exports = { sendVerificationEmail };
