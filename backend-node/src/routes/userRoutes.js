const express = require("express");
const router = express.Router();
const supabase = require("../config/supabaseClient");
const jwt = require("jsonwebtoken");
const config = require("../config/env");
const { tokenRequired } = require("../middleware/authMiddleware"); // JWT middleware


// ------------------------------------------------------------------------------
// 📌 User Profile Route - Fetch User Data
// ------------------------------------------------------------------------------
router.get("/user_profile", tokenRequired, async (req, res) => {
  try {
    const userId = req.user_id; // ✅ Extracted from JWT middleware

    // ✅ Fetch user data from Supabase
    const { data, error } = await supabase
      .from("user_profiles")
      .select("*")
      .eq("id", userId)
      .single();

    if (error || !data) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json(data); // ✅ Return user profile data as JSON
  } catch (err) {
    console.error("Error fetching user profile:", err);
    res.status(500).json({ error: "Failed to load user profile" });
  }
});

// ------------------------------------------------------------------------------
// ⚙️ User Settings Route (If Needed)
// ------------------------------------------------------------------------------
router.get("/settings", tokenRequired, (req, res) => {
  try {
    const settingsType = req.query.type || "general"; // Default to 'general'
    res.json({ message: `Settings page for: ${settingsType}` });
  } catch (err) {
    console.error("Error loading settings:", err);
    res.status(500).json({ error: "Failed to load settings" });
  }
});

module.exports = router;
