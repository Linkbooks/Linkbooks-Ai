const express = require("express");
const router = express.Router();
const { quickbooksLogin, callback } = require("../controllers/quickbooksController");

router.get("/quickbooks-login", quickbooksLogin);
router.get("/callback", callback);

module.exports = router;
