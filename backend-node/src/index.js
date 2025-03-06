require("dotenv").config(); // Load environment variables

const { initializeSocket } = require("./config/extensions");
const express = require("express");
const path = require("path");
const app = require("./app"); // ✅ Import Express App
const config = require("./config/env");

// ✅ Create HTTP Server
const server = require("http").createServer(app);
const io = initializeSocket(server); // ✅ Attach WebSocket

// ✅ Log Environment
console.log("🚀 Running in environment:", config.NODE_ENV);
console.log("🌍 Allowed CORS Origins:", config.ALLOWED_CORS_ORIGINS);

const PORT = process.env.PORT || 3000;

// ✅ Serve Static Frontend Files
const FRONTEND_BUILD_PATH = path.join(__dirname, "../frontend/build"); // Ensure this matches your build directory
app.use(express.static(FRONTEND_BUILD_PATH));

// ✅ Catch-all Route for Svelte Frontend (Only If No API Route Matched)
app.get("*", (req, res) => {
  res.sendFile(path.join(FRONTEND_BUILD_PATH, "index.html"));
});

// ✅ Start the server
server.listen(PORT, () => {
  console.log(`🔥 Server running on http://localhost:${PORT}`);
});
