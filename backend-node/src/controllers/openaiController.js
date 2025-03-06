const chatSessionService = require("../services/chatSessionService");
const openaiService = require("../services/openaiService");

// ✅ Start OAuth for ChatGPT
exports.startOAuthForChatGPT = async (req, res) => {
  try {
    const chatSessionId = req.query.chatSessionId || chatSessionService.generateSessionId();
    const authData = await chatSessionService.initiateOAuthFlow(chatSessionId);
    
    res.json(authData);

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// ✅ Link ChatGPT Chat Session to User
exports.linkChatSession = async (req, res) => {
  try {
    const { chatSessionId, sessionToken } = req.query;
    const result = await chatSessionService.linkChatSession(chatSessionId, sessionToken);

    res.json(result);

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// ✅ Fetch User Preferences
exports.fetchPreferences = async (req, res) => {
  try {
    const chatSessionId = req.query.chatSessionId;
    const preferences = await openaiService.getUserPreferences(chatSessionId);

    res.json(preferences);

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// ✅ Update User Preferences
exports.updatePreferences = async (req, res) => {
  try {
    const { chatSessionId, personalizationNote } = req.body;
    const updateResult = await openaiService.updateUserPreferences(chatSessionId, personalizationNote);

    res.json(updateResult);

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// ✅ Test OpenAI API
exports.testOpenAI = async (req, res) => {
  try {
    const testResponse = await openaiService.testOpenAIConnection();
    res.json(testResponse);

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// ✅ Test OpenAI API Key
exports.testOpenAIKey = async (req, res) => {
  try {
    const keyValidation = await openaiService.validateOpenAIKey();
    res.json(keyValidation);

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};
