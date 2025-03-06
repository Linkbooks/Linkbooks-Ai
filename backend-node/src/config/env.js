console.log("Loaded ENV:", process.env.SECRET_KEY);

require("dotenv").config(); // Load .env variables

const NODE_ENV = process.env.NODE_ENV || "production";

const config = {
  // ✅ Environment & Debugging
  NODE_ENV,
  DEBUG: NODE_ENV === "development",

  // ✅ Security & Authentication
  SECRET_KEY: process.env.SECRET_KEY,
  JWT_SECRET_KEY: process.env.JWT_SECRET_KEY,

  // ✅ Session & Cookie Settings
  SESSION_COOKIE_SECURE: NODE_ENV !== "development",
  SESSION_COOKIE_DOMAIN: NODE_ENV === "development" ? null : ".linkbooksai.com",
  SESSION_COOKIE_HTTPONLY: true,

  // ✅ Frontend URL
  FRONTEND_URL: process.env.FRONTEND_URL || "http://localhost:5173",

  // ✅ OpenAI Configuration
  OPENAI_API_KEY: process.env.OPENAI_API_KEY,
  OPENAI_ASSISTANT_ID: process.env.OPENAI_ASSISTANT_ID,

  // ✅ Supabase Configuration
  SUPABASE_URL: process.env.SUPABASE_URL,
  SUPABASE_KEY: process.env.SUPABASE_KEY,

  // ✅ Stripe Configuration
  STRIPE_SECRET_KEY: process.env.STRIPE_SECRET_KEY,
  STRIPE_PUBLIC_KEY: process.env.STRIPE_PUBLIC_KEY,

  // ✅ Brevo Configuration
  BREVO_API_KEY: process.env.BREVO_API_KEY,
  BREVO_SEND_EMAIL_URL: "https://api.brevo.com/v3/smtp/email",

  // ✅ Email Configuration (Brevo, Mailgun, etc.)
  MAIL_SERVER: process.env.MAIL_SERVER,
  MAIL_PORT: parseInt(process.env.MAIL_PORT, 10) || 587,
  MAIL_USE_TLS: process.env.MAIL_USE_TLS === "True",
  MAIL_USERNAME: process.env.MAIL_USERNAME,
  MAIL_PASSWORD: process.env.MAIL_PASSWORD,

  // ✅ CORS Configuration
  CORS_ORIGIN: NODE_ENV === "development" ? process.env.CORS_ORIGIN_LOCAL : process.env.CORS_ORIGIN,
  ALLOWED_CORS_ORIGINS: [
    "https://linkbooksai.com",
    "https://app.linkbooksai.com",
    ...(NODE_ENV === "development" ? ["http://localhost:5173"] : []),
  ],

  // ✅ WebSocket Configuration
  SOCKETIO_CORS_ALLOWED_ORIGINS: [
    "https://linkbooksai.com",
    "https://app.linkbooksai.com",
    ...(NODE_ENV === "development" ? ["http://localhost:5173"] : []),
  ],
  SOCKETIO_TRANSPORTS: ["websocket"], // Force WebSockets (no polling)
  SOCKETIO_PING_INTERVAL: 25, // Keep connection alive
  SOCKETIO_PING_TIMEOUT: 60, // Prevent WebSocket closing too soon

  // ✅ QuickBooks OAuth Settings
  QUICKBOOKS: {
    CLIENT_ID: NODE_ENV === "development" ? process.env.QB_SANDBOX_CLIENT_ID : process.env.QB_PROD_CLIENT_ID,
    CLIENT_SECRET: NODE_ENV === "development" ? process.env.QB_SANDBOX_CLIENT_SECRET : process.env.QB_PROD_CLIENT_SECRET,
    REDIRECT_URI: NODE_ENV === "development" ? process.env.SANDBOX_REDIRECT_URI : process.env.PROD_REDIRECT_URI,
    API_BASE_URL:
      NODE_ENV === "development"
        ? "https://sandbox-quickbooks.api.intuit.com/v3/company/"
        : "https://quickbooks.api.intuit.com/v3/company/",
    AUTHORIZATION_BASE_URL: "https://appcenter.intuit.com/connect/oauth2",
    TOKEN_URL: "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer",
    SCOPE: "com.intuit.quickbooks.accounting",
    REVOKE_TOKEN_URL: "https://developer.api.intuit.com/v2/oauth2/tokens/revoke",
  },
};

// ✅ Validate Required Environment Variables
const REQUIRED_ENV_VARS = [
  "SUPABASE_URL",
  "SUPABASE_KEY",
  "SECRET_KEY",
];

if (NODE_ENV === "development") {
  REQUIRED_ENV_VARS.push(
    "QB_SANDBOX_CLIENT_ID",
    "QB_SANDBOX_CLIENT_SECRET",
    "SANDBOX_REDIRECT_URI"
  );
} else {
  REQUIRED_ENV_VARS.push(
    "QB_PROD_CLIENT_ID",
    "QB_PROD_CLIENT_SECRET",
    "PROD_REDIRECT_URI"
  );
}

// ✅ Check for missing environment variables
const missingVars = REQUIRED_ENV_VARS.filter((varName) => !process.env[varName]);
if (missingVars.length > 0) {
  throw new Error(`Missing required environment variables: ${missingVars.join(", ")}`);
}

// ✅ Log Environment Variables (Masked for Security)
if (NODE_ENV === "development") {
  console.log("✅ Loaded Environment Variables:");
  REQUIRED_ENV_VARS.forEach((key) => {
    const maskedValue = key.includes("KEY") || key.includes("SECRET") ? "*****" : process.env[key];
    console.log(`${key}: ${maskedValue}`);
  });
}

module.exports = config;
