const express = require("express");
const router = express.Router();
const legalController = require("../controllers/legalController");

router.get("/eula", legalController.eula);  // ✅ Serves the EULA page
router.get("/privacy-policy", legalController.privacyPolicy);  // ✅ Serves the Privacy Policy page

module.exports = router;
