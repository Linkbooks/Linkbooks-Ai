const express = require("express");
const router = express.Router();
const dashboardController = require("../controllers/dashboardController");

router.get("/dashboard", dashboardController.dashboard);
router.get("/api/dashboard-data", dashboardController.getDashboardData);
router.get("/session/status", dashboardController.getSessionStatus);

module.exports = router;
