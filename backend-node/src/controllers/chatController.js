const chatService = require("../services/chatService");

// Process a chat message and return the response.
exports.processMessage = async (req, res) => {
  try {
    const { session_token, message } = req.body;

    if (!session_token || !message) {
      return res.status(400).json({ error: "Session token and message are required." });
    }

    const result = await chatService.processAndStreamResponse(session_token, message);
    res.json(result);

  } catch (error) {
    res.status(500).json({ error: "An error occurred while processing the chat message." });
  }
};
