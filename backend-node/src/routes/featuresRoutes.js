const express = require("express");
const router = express.Router();
const featuresController = require("../controllers/featuresController");

// ✅ Features API Routes
router.get("/business-info", featuresController.getBusinessInfo);  // ✅ Get business info from QuickBooks
router.get("/fetch-reports", featuresController.fetchReports);    // ✅ Fetch QuickBooks reports
router.get("/list-reports", featuresController.listReports);      // ✅ List all available reports
router.post("/analyze-reports", featuresController.analyzeReports);  // ✅ Send reports to OpenAI for analysis
router.get("/fetch-transactions-ai", featuresController.fetchTransactionsAI);  // ✅ Fetch and filter transactions using AI
router.get("/fetch-transactions", featuresController.fetchTransactions);  // ✅ Fetch QuickBooks transactions (classic)
router.post("/filter-transactions", featuresController.filterTransactions);  // ✅ AI-assisted transaction filtering
router.get("/audit", featuresController.auditCompany);  // ✅ Perform company audit & AI insights

module.exports = router;
