const axios = require("axios");
const jwt = require("jsonwebtoken");
const supabase = require("../config/supabaseClient");
const {
  CLIENT_ID,
  CLIENT_SECRET,
  TOKEN_URL,
  REVOKE_TOKEN_URL,
  JWT_SECRET_KEY,
} = require("../config/quickbooksConfig");

/**
 * Retrieves `user_id` from either session token or chatSessionId.
 */
const getUserIdFromSession = async (sessionToken, chatSessionId) => {
  let userId = null;

  if (sessionToken) {
    try {
      const decoded = jwt.verify(sessionToken, JWT_SECRET_KEY);
      userId = decoded.user_id;
    } catch {
      throw new Error("Invalid or expired session token.");
    }
  }

  if (!userId && chatSessionId) {
    const { data, error } = await supabase
      .from("user_profiles")
      .select("id")
      .eq("chat_session_id", chatSessionId)
      .single();

    if (error) throw new Error("Failed to retrieve user from chatSessionId.");
    userId = data?.id || null;
  }

  return userId;
};

/**
 * Fetches QuickBooks tokens for a given `user_id`.
 */
const getQuickBooksTokens = async (userId) => {
  const { data, error } = await supabase
    .from("quickbooks_tokens")
    .select("*")
    .eq("user_id", userId)
    .single();

  if (error || !data) throw new Error("No QuickBooks tokens found.");
  return data;
};

/**
 * Saves QuickBooks tokens (upserts to prevent duplicates).
 */
const saveQuickBooksTokens = async (userId, realmId, accessToken, refreshToken, tokenExpiry) => {
  try {
    await supabase
      .from("quickbooks_tokens")
      .upsert({
        user_id: userId,
        realm_id: realmId,
        access_token: accessToken,
        refresh_token: refreshToken,
        token_expiry: tokenExpiry,
        last_updated: new Date().toISOString(),
      });

    console.log(`✅ QuickBooks tokens saved for user ${userId}`);
  } catch (error) {
    console.error(`❌ Error saving QuickBooks tokens for user ${userId}:`, error.message);
    throw new Error("Failed to save QuickBooks tokens.");
  }
};

/**
 * Refreshes QuickBooks access token using the stored refresh token.
 */
const refreshAccessToken = async (userId) => {
  try {
    const { refresh_token, realm_id } = await getQuickBooksTokens(userId);

    const response = await axios.post(
      TOKEN_URL,
      new URLSearchParams({ grant_type: "refresh_token", refresh_token }),
      { auth: { username: CLIENT_ID, password: CLIENT_SECRET } }
    );

    const { access_token, refresh_token: newRefreshToken, expires_in } = response.data;
    const tokenExpiry = new Date(Date.now() + expires_in * 1000).toISOString();

    await saveQuickBooksTokens(userId, realm_id, access_token, newRefreshToken, tokenExpiry);
    return { access_token, realm_id };
  } catch (error) {
    console.error("❌ Failed to refresh QuickBooks tokens:", error.message);
    throw new Error("Token refresh failed.");
  }
};

/**
 * Revokes QuickBooks tokens.
 */
const revokeQuickBooksTokens = async (refreshToken) => {
  try {
    await axios.post(
      REVOKE_TOKEN_URL,
      new URLSearchParams({ token: refreshToken }),
      { auth: { username: CLIENT_ID, password: CLIENT_SECRET } }
    );
    console.log("✅ QuickBooks tokens revoked successfully.");
  } catch (error) {
    console.error("❌ Error revoking QuickBooks tokens:", error.message);
    throw new Error("Failed to revoke QuickBooks tokens.");
  }
};

/**
 * Fetches QuickBooks Company Info.
 */
const getCompanyInfo = async (userId) => {
  return await getQuickBooksTokens(userId);
};

module.exports = {
  getUserIdFromSession,
  getQuickBooksTokens,
  saveQuickBooksTokens,
  refreshAccessToken,
  revokeQuickBooksTokens,
  getCompanyInfo,
};
