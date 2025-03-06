const authService = require('../services/authService');
const jwt = require("jsonwebtoken");

// Login
exports.login = async (req, res) => {
  try {
    const { email, password, chatSessionId } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error_message: "Email and password are required." });
    }

    const result = await authService.login(email, password, chatSessionId);

    // ✅ Set session_token as an HTTP-only cookie
    res.cookie("session_token", result.session_token, {
      httpOnly: true, // ✅ Secure against XSS attacks
      secure: process.env.NODE_ENV === "production", // ✅ Use secure cookies in production (HTTPS required)
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax", // ✅ Required for cross-origin authentication
      domain: process.env.NODE_ENV === "production" ? ".linkbooksai.com" : undefined, // ✅ Ensures cookies work across subdomains
    });


    return res.json({ success: true, redirect_url: "/dashboard" });

  } catch (err) {
    return res.status(err.status || 500).json({ error_message: err.message });
  }
};


// Logout
exports.logout = async (req, res) => {
  try {
    const sessionToken = req.cookies.session_token || req.cookies.session;
    if (!sessionToken) {
      return res.status(401).json({ success: false, message: "No active session found." });
    }

    await authService.logout(sessionToken);
    res.clearCookie("session_token");
    res.clearCookie("session");
    res.json({ success: true, message: "You have been logged out successfully." });

  } catch (err) {
    res.status(500).json({ success: false, message: "An error occurred during logout." });
  }
};

// Check Auth Status
exports.checkAuthStatus = async (req, res) => {
  const sessionToken = req.cookies.session_token;

  if (!sessionToken) {
    return res.status(401).json({ logged_in: false, message: "No session token found" });
  }

  try {
    // ✅ Verify token
    const decoded = jwt.verify(sessionToken, process.env.JWT_SECRET_KEY);

    // ✅ If verification is successful, return user_id
    return res.json({ logged_in: true, user_id: decoded.user_id });
  } catch (error) {
    console.error("❌ Invalid session token:", error);
    return res.status(401).json({ logged_in: false, message: "Invalid or expired session token" });
  }
};


// Get Session
exports.getSession = async (req, res) => {
  try {
    const sessionData = await authService.getSession(req.cookies.session_token);
    res.json(sessionData);
  } catch (err) {
    res.status(500).json({ error: "Failed to retrieve session data" });
  }
};

// Create Account
exports.createAccount = async (req, res) => {
  try {
    const newUser = await authService.createAccount(req.body);
    res.json(newUser);
  } catch (err) {
    res.status(err.status || 500).json({ error_message: err.message });
  }
};

// Fetch User Data
exports.fetchUserData = async (req, res) => {
  try {
    const userData = await authService.fetchUserData(req.user_id);
    res.json(userData);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};
