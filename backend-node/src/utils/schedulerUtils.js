const cron = require("node-cron");
const supabase = require("../config/supabaseClient");
const logger = require("./loggingUtils");

/**
 * Deletes expired chat session OAuth states.
 */
const cleanupExpiredStates = async () => {
  try {
    const now = new Date().toISOString();
    await supabase.from("chatgpt_oauth_states").delete().lt("expiry", now);
    logger.info("✅ Expired state tokens cleaned up.");
  } catch (error) {
    logger.error(`❌ Error cleaning up expired states: ${error.message}`);
  }
};

/**
 * Starts all scheduled jobs.
 */
const startScheduler = () => {
  logger.info("🚀 Scheduler started!");

  // ✅ Schedule Cleanup Jobs
  cron.schedule("0 */3 * * *", cleanupExpiredStates); // Every 3 hours
};

module.exports = { cleanupExpiredStates, startScheduler };
