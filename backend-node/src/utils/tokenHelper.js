const jwt = require('jsonwebtoken');
const config = require("../config/env");

exports.generateSessionToken = (user_id, email) => {
  return jwt.sign(
    { user_id, email },
    process.env.JWT_SECRET_KEY,
    { expiresIn: "24h" }
  );
};

exports.verifySessionToken = (token) => {
  return jwt.verify(token, process.env.JWT_SECRET_KEY);
};


exports.verifyToken = (token) => {
  try {
    return jwt.verify(token, config.NODE_SECRET_KEY);
  } catch (err) {
    throw new Error("Invalid or expired token");
  }
};
