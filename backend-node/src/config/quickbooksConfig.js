require("dotenv").config();

module.exports = {
  CLIENT_ID: process.env.QB_CLIENT_ID,
  CLIENT_SECRET: process.env.QB_CLIENT_SECRET,
  REDIRECT_URI: process.env.QB_REDIRECT_URI,
  AUTHORIZATION_BASE_URL: process.env.QB_AUTHORIZATION_BASE_URL,
  TOKEN_URL: process.env.QB_TOKEN_URL,
  REVOKE_TOKEN_URL: process.env.QB_REVOKE_TOKEN_URL,
  SCOPE: "com.intuit.quickbooks.accounting",
  SECRET_KEY: process.env.NODE_SECRET_KEY, // Ensure this is correct
};