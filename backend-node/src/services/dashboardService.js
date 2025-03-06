const supabase = require("../config/supabaseClient");
const jwt = require("jsonwebtoken");
const config = require("../config/env");

// Get Dashboard Data
exports.getDashboardData = async (token, chatSessionId) => {
  try {    
    let user_id;
    try {
      const decoded = jwt.verify(token, config.JWT_SECRET_KEY);
      user_id = decoded.user_id;
    } catch (err) {
      console.error("❌ Token Error:", err.message);
      throw new Error("Invalid or expired token");
    }


    // ✅ QuickBooks Status Check
    let quickbooksLoginNeeded = true;
    const { data: quickbooksData } = await supabase
      .from("quickbooks_tokens")
      .select("access_token, token_expiry")
      .eq("user_id", user_id)
      .single();

    if (quickbooksData && quickbooksData.access_token) {
      const expiry = new Date(quickbooksData.token_expiry);
      if (expiry > new Date()) {
        quickbooksLoginNeeded = false; // ✅ QuickBooks is connected
      }
    }

    // ✅ Fetch active ChatGPT sessions
    let chatgptSessions = [];
    const { data: sessions } = await supabase
      .from("chatgpt_oauth_states")
      .select("chat_session_id, expiry, created_at")
      .eq("user_id", user_id);

    if (sessions) {
      chatgptSessions = sessions
        .filter((session) => session.chat_session_id)
        .map((session) => ({
          chatSessionId: session.chat_session_id.toString(),
          expiry: session.expiry,
          createdAt: session.created_at,
        }));
    }

    return {
      success: true,
      quickbooks_login_needed: quickbooksLoginNeeded,
      chatSessionId: chatSessionId || "",
      chatgpt_sessions: chatgptSessions,
    };

  } catch (error) {
    console.error(`Error in getDashboardData: ${error.message}`);
    throw new Error("An error occurred while retrieving dashboard data.");
  }
};

// Get Session Status
exports.getSessionStatus = async (chatSessionId) => {
  try {
    const { data: tokens } = await supabase
      .from("chatgpt_tokens")
      .select("*")
      .eq("chat_session_id", chatSessionId)
      .single();

    if (!tokens) {
      return { authenticated: false, message: "No tokens found. Please log in." };
    }

    const expiry = new Date(tokens.expiry);
    if (new Date() > expiry) {
      return { authenticated: false, message: "Session expired. Please reauthenticate." };
    }

    return { authenticated: true, message: "Session is active." };

  } catch (error) {
    console.error(`Error in getSessionStatus: ${error.message}`);
    throw new Error("An error occurred while checking session status.");
  }
};
