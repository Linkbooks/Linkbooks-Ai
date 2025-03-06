const jwt = require("jsonwebtoken");
const axios = require("axios");
const supabase = require("../config/supabaseClient");
const { CLIENT_ID, CLIENT_SECRET, REDIRECT_URI, AUTHORIZATION_BASE_URL, SCOPE, JWT_SECRET_KEY } = require("../config/quickbooksConfig");
const { refreshAccessToken } = require("../services/quickbooksService");
const { generateRandomState } = require("../utils/securityUtils");

/**
 * Initiates QuickBooks OAuth process.
 */
const quickbooksLogin = async (req, res) => {
  try {
    const sessionToken = req.cookies.session_token;
    if (!sessionToken) return res.status(401).json({ error: "User not authenticated." });

    const decoded = jwt.verify(sessionToken, JWT_SECRET_KEY);
    const userId = decoded.user_id;

    if (!userId) return res.status(401).json({ error: "Invalid session token." });

    const state = generateRandomState();

    await supabase.from("chatgpt_oauth_states").upsert({
      user_id: userId,
      state,
      expiry: new Date(Date.now() + 30 * 60 * 1000).toISOString(),
      is_authenticated: false,
    });

    const authUrl = `${AUTHORIZATION_BASE_URL}?client_id=${CLIENT_ID}&response_type=code&scope=${SCOPE}&redirect_uri=${REDIRECT_URI}&state=${state}`;
    res.redirect(authUrl);
  } catch (error) {
    console.error("Error in QuickBooks login:", error.message);
    res.status(500).json({ error: "OAuth initiation failed." });
  }
};

/**
 * Handles QuickBooks OAuth callback.
 */
const callback = async (req, res) => {
  try {
    const { code, realmId, state } = req.query;
    if (!code || !realmId || !state) return res.status(400).json({ error: "Missing required parameters." });

    const { data: storedState } = await supabase.from("chatgpt_oauth_states").select("user_id").eq("state", state).single();
    if (!storedState) return res.status(400).json({ error: "Invalid or expired state." });

    const userId = storedState.user_id;

    const response = await axios.post(
      TOKEN_URL,
      new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI }),
      { auth: { username: CLIENT_ID, password: CLIENT_SECRET } }
    );

    const { access_token, refresh_token, expires_in } = response.data;
    const tokenExpiry = new Date(Date.now() + expires_in * 1000).toISOString();

    await supabase.from("quickbooks_tokens").upsert({
      user_id: userId,
      realm_id: realmId,
      access_token,
      refresh_token,
      token_expiry: tokenExpiry,
    });

    res.redirect("/dashboard?quickbooks_login_success=true");
  } catch (error) {
    console.error("Error in QuickBooks callback:", error.message);
    res.status(500).json({ error: "OAuth callback failed." });
  }
};

module.exports = { quickbooksLogin, callback };
