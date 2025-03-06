const express = require("express");
const router = express.Router();
const openaiController = require("../controllers/openaiController");

router.get("/oauth/start-for-chatgpt", openaiController.startOAuthForChatGPT);   // ✅ Start OAuth Flow
router.get("/link-chat-session", openaiController.linkChatSession);   // ✅ Link chat session to user
router.get("/preferences", openaiController.fetchPreferences);   // ✅ Get AI user preferences
router.post("/preferences/update", openaiController.updatePreferences);   // ✅ Update AI user preferences
router.get("/test-openai", openaiController.testOpenAI);   // ✅ Test OpenAI API
router.get("/test-openai-key", openaiController.testOpenAIKey);   // ✅ Check if OpenAI API Key is valid

module.exports = router;
