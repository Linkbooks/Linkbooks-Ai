const jwt = require("jsonwebtoken");
const config = require("../config/env");

/**
 * Generates a random OAuth state string.
 */
const generateRandomState = (length = 16) => {
  const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  return Array.from({ length }, () => characters[Math.floor(Math.random() * characters.length)]).join("");
};

/**
 * Middleware to verify JWT token from cookies.
 */
const tokenRequired = (req, res, next) => {
  const token = req.cookies.session_token;
  if (!token) return res.status(401).json({ error: "No authorization token provided" });

  try {
    const decoded = jwt.verify(token, config.JWT_SECRET_KEY);
    req.user_id = decoded.user_id;
    if (!req.user_id) throw new Error("No user_id found in token.");
    next();
  } catch (error) {
    res.status(401).json({ error: "Invalid or expired token." });
  }
};

module.exports = { generateRandomState, tokenRequired };
