const dashboardService = require("../services/dashboardService");


// Serve the dashboard page
exports.dashboard = (req, res) => {
  try {
    const token = req.cookies.session_token;
    if (!token) {
      return res.redirect("/login");
    }

    // Serve the Svelte frontend dashboard page
    res.sendFile("index.html", { root: "./public" });
  } catch (error) {
    res.status(500).json({ error: "An error occurred while loading the dashboard." });
  }
};

// Get the dashboard data for the user
exports.getDashboardData = async (req, res) => {
  try {
    const token = req.cookies.session_token;
    if (!token) {
      return res.status(401).json({ error: "User not authenticated" });
    }

    const dashboardData = await dashboardService.getDashboardData(token, req.query.chatSessionId);
    res.json(dashboardData);

  } catch (error) {
    console.error(`Error in /api/dashboard-data: ${error.message}`);
    res.status(500).json({ error: error.message });
  }
};

// Get the status of a chat session
exports.getSessionStatus = async (req, res) => {
  try {
    const chatSessionId = req.query.chatSessionId;
    if (!chatSessionId) {
      return res.status(400).json({ authenticated: false, message: "chatSessionId is required" });
    }

    const sessionStatus = await dashboardService.getSessionStatus(chatSessionId);
    res.json(sessionStatus);

  } catch (error) {
    console.error(`Error in /session/status: ${error.message}`);
    res.status(500).json({ authenticated: false, message: "An unexpected error occurred. Try again later." });
  }
};
