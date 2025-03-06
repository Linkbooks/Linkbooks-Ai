const jwt = require("jsonwebtoken");
const config = require("../config/env");

exports.tokenRequired = (req, res, next) => {
  try {
    const token = req.cookies.session_token || req.headers.authorization?.split(" ")[1];

    if (!token) {
      return res.status(401).json({ error: "Unauthorized: No token provided" });
    }

    // Verify JWT
    const decoded = jwt.verify(token, config.JWT_SECRET_KEY);
    req.user_id = decoded.user_id; // Attach user ID to request

    next(); // ✅ Proceed to the next middleware or route
  } catch (err) {
    res.status(401).json({ error: "Unauthorized: Invalid or expired token" });
  }
};
