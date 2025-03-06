const supabase = require("../config/supabaseClient");
const logger = require("./loggingUtils");

logger.info(`✅ Validating OAuth state: ${state}`);

/**
 * Validates the incoming OAuth state against `chatgpt_oauth_states`.
 * Ensures the state exists and hasn't expired.
 */
const validateState = async (state) => {
  const { data, error } = await supabase
    .from("chatgpt_oauth_states")
    .select("*")
    .eq("state", state)
    .single();

  if (error || !data) {
    logger.error(`❌ Invalid or expired OAuth state: ${state}`);
    throw new Error("Invalid or expired state parameter.");
  }

  const expiry = new Date(data.expiry);
  if (new Date() > expiry) {
    logger.error(`❌ State expired: Generated: ${data.expiry} Current: ${new Date()}`);
    throw new Error("State token expired.");
  }

  return data;
};

module.exports = { validateState };
