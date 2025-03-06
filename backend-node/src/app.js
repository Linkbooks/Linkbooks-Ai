require("dotenv").config(); // Load environment variables

const express = require("express");
const cors = require("cors"); // ✅ Import cors
const { corsOptions, limiter, cookieParser } = require("./config/extensions");
const { startScheduler } = require("./utils/schedulerUtils");

// ✅ Import Routes
const authRoutes = require("./routes/authRoutes");
const quickbooksRoutes = require("./routes/quickbooksRoutes");
const chatRoutes = require("./routes/chatRoutes");
const paymentsRoutes = require("./routes/paymentsRoutes");
const openaiRoutes = require("./routes/openaiRoutes");
const dashboardRoutes = require("./routes/dashboardRoutes");
const legalRoutes = require("./routes/legalRoutes");
const featuresRoutes = require("./routes/featuresRoutes");
const userRoutes = require("./routes/userRoutes");

// ✅ Setup Logging
const logger = require("./utils/loggingUtils"); // ✅ Import logger

logger.info("✅ Logging initialized."); // ✅ Log that logging is set up

// ✅ Initialize Express App
const app = express();



// ✅ Middleware
app.use(express.json()); // Parse JSON requests
app.use(express.urlencoded({ extended: true })); // ✅ Parse x-www-form-urlencoded requests
app.use(cookieParser()); // Enable Cookie Parsing
app.use(cors(corsOptions)); // Enable CORS
app.use(limiter); // Apply Rate Limiting

// ✅ Register Routes
app.use("/auth", authRoutes);
app.use("/quickbooks", quickbooksRoutes);
app.use("/chat", chatRoutes);
app.use("/payments", paymentsRoutes);
app.use("/openai", openaiRoutes);
app.use("/dashboard", dashboardRoutes);
app.use("/user", userRoutes);
app.use("/legal", legalRoutes);
app.use("/features", featuresRoutes);

// ✅ Start Scheduled Jobs
startScheduler();

// ✅ Debug Route
app.get("/debug-env", (req, res) => {
  if (process.env.NODE_ENV !== "development") {
    return res.status(403).json({ error: "Not authorized." });
  }
  return res.json({
    SUPABASE_URL: process.env.SUPABASE_URL,
    SUPABASE_KEY: "*****",
    QUICKBOOKS_CLIENT_ID: "*****",
    QUICKBOOKS_CLIENT_SECRET: "*****",
    NODE_SECRET_KEY: "*****",
    OPENAI_API_KEY: "*****",
  });
});

// ✅ Export Express App
module.exports = app;
