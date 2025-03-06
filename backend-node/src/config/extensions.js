const supabase = require("./supabaseClient"); // ✅ Use centralized Supabase client
const OpenAI = require("openai");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const { Server } = require("socket.io");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);

// ✅ Initialize OpenAI Client
const openaiClient = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

// ✅ CORS Middleware (Check if variable exists)
const corsOptions = {
  origin: process.env.ALLOWED_CORS_ORIGINS
    ? process.env.ALLOWED_CORS_ORIGINS.split(",")
    : ["https://linkbooksai.com", "https://app.linkbooksai.com"],
  credentials: true,
};

// ✅ Rate Limiter
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
});

// ✅ WebSocket Initialization (Check if variable exists)
const initializeSocket = (server) => {
  const io = new Server(server, {
    cors: {
      origin: process.env.SOCKETIO_CORS_ALLOWED_ORIGINS
        ? process.env.SOCKETIO_CORS_ALLOWED_ORIGINS.split(",")
        : ["https://linkbooksai.com", "https://app.linkbooksai.com"],
      methods: ["GET", "POST"],
    },
    transports: process.env.SOCKETIO_TRANSPORTS
      ? process.env.SOCKETIO_TRANSPORTS.split(",")
      : ["websocket", "polling"],
    pingInterval: Number(process.env.SOCKETIO_PING_INTERVAL) || 25000,
    pingTimeout: Number(process.env.SOCKETIO_PING_TIMEOUT) || 60000,
  });

  io.on("connection", (socket) => {
    console.log("🟢 WebSocket connected:", socket.id);
    socket.on("disconnect", () =>
      console.log("🔴 WebSocket disconnected:", socket.id)
    );
  });

  return io;
};

// ✅ Export All Services
module.exports = {
  supabase, // ✅ Now using the dedicated `supabaseClient.js`
  openaiClient,
  stripe,
  corsOptions,
  limiter,
  cookieParser,
  initializeSocket,
};
