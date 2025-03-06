const path = require("path");

// ✅ Serve EULA Page
exports.eula = (req, res) => {
  res.sendFile(path.join(__dirname, "../views/eula.html"));
};

// ✅ Serve Privacy Policy Page
exports.privacyPolicy = (req, res) => {
  res.sendFile(path.join(__dirname, "../views/privacy_policy.html"));
};
