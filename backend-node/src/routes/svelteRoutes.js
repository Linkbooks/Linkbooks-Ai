const express = require("express");
const path = require("path");

const router = express.Router();

// ✅ Serve Static Assets for Svelte
router.use("/assets", express.static(path.join(__dirname, "../../frontend/static/assets")));

// ✅ Serve Svelte Frontend Files
router.get("*", (req, res) => {
  const blueprintPrefixes = ["/api", "/auth", "/quickbooks", "/chat", "/payments", "/chatgpt", "/legal"];

  // 🛑 Skip serving Svelte if the request is for an API or backend route
  if (blueprintPrefixes.some(prefix => req.path.startsWith(prefix))) {
    return res.status(404).send("Not Found");
  }

  // ✅ Serve Svelte's `index.html` for all frontend routes (SPA behavior)
  res.sendFile(path.join(__dirname, "../../frontend/dist/index.html"));
});

module.exports = router;
