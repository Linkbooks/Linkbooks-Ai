const supabase = require("../config/supabaseClient");
const jwt = require("jsonwebtoken");
const config = require("../config/env");

exports.generateSessionId = () => {
  return crypto.randomUUID();
};

exports.initiateOAuthFlow = async (chatSessionId) => {
  const user = await supabase
    .from("user_profiles")
    .select("id")
    .eq("chat_session_id", chatSessionId)
    .single();

  if (!user.data) {
    return { loginUrl: `https://linkbooksai.com/login?chatSessionId=${chatSessionId}`, chatSessionId };
  }

  const oauthState = {
    chatSessionId,
    userId: user.data.id,
    state: "initiated",
    expiry: new Date(Date.now() + 30 * 60000).toISOString(),
  };

  await supabase.from("chatgpt_oauth_states").upsert(oauthState);
  return { authenticated: true, chatSessionId };
};

exports.linkChatSession = async (chatSessionId, sessionToken) => {
  const decoded = jwt.verify(sessionToken, config.JWT_SECRET_KEY);
  if (!decoded.user_id) throw new Error("Invalid session token.");

  const result = await supabase
    .from("chatgpt_oauth_states")
    .update({ user_id: decoded.user_id })
    .eq("chat_session_id", chatSessionId);

  return { message: "Chat session linked successfully." };
};
