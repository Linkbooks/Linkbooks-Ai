const quickbooksService = require("../services/quickbooksService");
const reportsService = require("../services/reportsService");
const transactionsService = require("../services/transactionsService");
const { datetimeFormat } = require("../utils/filters");

// ✅ Get Business Information from QuickBooks
exports.getBusinessInfo = async (req, res) => {
  try {
    const { session_token } = req.cookies;
    const chatSessionId = req.query.chatSessionId;

    if (!session_token && !chatSessionId) {
      return res.status(400).json({ error: "chatSessionId or session_token is required" });
    }

    const user_id = await quickbooksService.getUserIdFromSession(session_token, chatSessionId);
    if (!user_id) return res.status(401).json({ error: "User not authenticated" });

    const companyInfo = await quickbooksService.getCompanyInfo(user_id);
    return res.json(companyInfo);

  } catch (error) {
    console.error("❌ Error in getBusinessInfo:", error);
    return res.status(500).json({ error: "Failed to retrieve business info." });
  }
};

// ✅ Fetch Financial Reports from QuickBooks (with Date Formatting)
exports.fetchReports = async (req, res) => {
  try {
    const { session_token } = req.cookies;
    const chatSessionId = req.query.chatSessionId;
    const { reportType, startDate, endDate } = req.query;

    if (!reportType) return res.status(400).json({ error: "reportType is required" });

    const user_id = await quickbooksService.getUserIdFromSession(session_token, chatSessionId);
    if (!user_id) return res.status(401).json({ error: "User not authenticated" });

    let reportData = await reportsService.fetchReport(user_id, reportType, startDate, endDate);

    // ✅ Apply datetime formatting to transactions before sending response
    if (reportData.transactions) {
      reportData.transactions = reportData.transactions.map((txn) => ({
        ...txn,
        formattedDate: datetimeFormat(txn.date),
      }));
    }

    return res.json({ reportType, data: reportData });

  } catch (error) {
    console.error("❌ Error fetching reports:", error);
    return res.status(500).json({ error: "Failed to fetch reports." });
  }
};

// ✅ List Available QuickBooks Reports
exports.listReports = (req, res) => {
  try {
    return res.json({ availableReports: reportsService.getAvailableReports() });
  } catch (error) {
    console.error("❌ Error listing reports:", error);
    return res.status(500).json({ error: "Failed to list available reports." });
  }
};

// ✅ Analyze Reports with OpenAI
exports.analyzeReports = async (req, res) => {
  try {
    const reports = req.body;
    if (!reports) return res.status(400).json({ error: "Report data is required." });

    const analysis = await reportsService.analyzeReports(reports);
    return res.json({ analysis, originalData: reports });

  } catch (error) {
    console.error("❌ Error analyzing reports:", error);
    return res.status(500).json({ error: "Failed to analyze reports." });
  }
};

// ✅ Fetch and AI-Filter Transactions
exports.fetchTransactionsAI = async (req, res) => {
  try {
    const { session_token } = req.cookies;
    const chatSessionId = req.query.chatSessionId;
    const { start_date, end_date, query } = req.query;

    if (!query) return res.status(400).json({ error: "Query parameter is required for AI filtering" });

    const user_id = await quickbooksService.getUserIdFromSession(session_token, chatSessionId);
    if (!user_id) return res.status(401).json({ error: "User not authenticated" });

    const transactions = await transactionsService.getTransactions(user_id, start_date, end_date);
    const filteredData = await transactionsService.filterTransactionsAI(transactions, query);

    return res.json({ transactions: filteredData });

  } catch (error) {
    console.error("❌ Error in fetchTransactionsAI:", error);
    return res.status(500).json({ error: "Failed to fetch and filter transactions using AI." });
  }
};

// ✅ Fetch Transactions (without AI filtering)
exports.fetchTransactions = async (req, res) => {
  try {
    const { session_token } = req.cookies;
    const chatSessionId = req.query.chatSessionId;
    const qb_params = req.query;

    const user_id = await quickbooksService.getUserIdFromSession(session_token, chatSessionId);
    if (!user_id) return res.status(401).json({ error: "User not authenticated" });

    const transactions = await transactionsService.getTransactions(user_id, qb_params);
    return res.json({ transactions });

  } catch (error) {
    console.error("❌ Error in fetchTransactions:", error);
    return res.status(500).json({ error: "Failed to fetch transactions." });
  }
};

exports.filterTransactions = async (req, res) => {
  try {
    const { session_token } = req.cookies;
    const chatSessionId = req.query.chatSessionId;
    const { filter_criteria } = req.body;

    if (!filter_criteria) {
      return res.status(400).json({ error: "Filter criteria is required" });
    }

    const user_id = await quickbooksService.getUserIdFromSession(session_token, chatSessionId);
    if (!user_id) return res.status(401).json({ error: "User not authenticated" });

    const filteredTransactions = await transactionsService.filterTransactions(user_id, filter_criteria);
    return res.json({ transactions: filteredTransactions });

  } catch (error) {
    console.error("❌ Error in filterTransactions:", error);
    return res.status(500).json({ error: "Failed to filter transactions." });
  }
};


// ✅ Perform AI-Assisted Company Audit
exports.auditCompany = async (req, res) => {
  try {
    const { session_token } = req.cookies;
    const chatSessionId = req.query.chatSessionId;

    const user_id = await quickbooksService.getUserIdFromSession(session_token, chatSessionId);
    if (!user_id) return res.status(401).json({ error: "User not authenticated" });

    const auditResult = await reportsService.auditCompany(user_id);
    return res.json(auditResult);

  } catch (error) {
    console.error("❌ Error in auditCompany:", error);
    return res.status(500).json({ error: "Failed to perform company audit." });
  }
};
