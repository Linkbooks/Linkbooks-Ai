const express = require("express");
const cookieParser = require("cookie-parser");

// Import Routes
const authRoutes = require("./authRoutes");
const userRoutes = require("./userRoutes");
const paymentsRoutes = require("./paymentsRoutes");
const transactionRoutes = require("./transactionRoutes");
const quickbooksRoutes = require("./quickbooksRoutes");
const chatRoutes = require("./chatRoutes");
const featuresRoutes = require("./featuresRoutes");
const legalRoutes = require("./legalRoutes");
const openaiRoutes = require("./openaiRoutes");
const dashboardRoutes = require("./dashboardRoutes");

const app = express();

// ✅ Middleware
app.use(express.json());
app.use(cookieParser());

// ✅ Register Routes Without `/api`
app.use("/auth", authRoutes);
app.use("/users", userRoutes);
app.use("/transactions", transactionRoutes);
app.use("/payments", paymentsRoutes);
app.use("/quickbooks", quickbooksRoutes);
app.use("/chat", chatRoutes);
app.use("/legal", legalRoutes);
app.use("/openai", openaiRoutes);
app.use("/features", featuresRoutes);
app.use("/dashboard", dashboardRoutes);

// ✅ Start Server (only if this is the main entry point, otherwise use `src/index.js`)
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));

module.exports = app;
