const express = require("express");
const router = express.Router();
const paymentsController = require("../controllers/paymentsController");

router.post("/subscriptions", paymentsController.createSubscription);  // ✅ Create subscription session
router.get("/subscriptions", paymentsController.getSubscriptionPage);  // ✅ Get subscription page

router.post("/stripe-webhook", paymentsController.handleStripeWebhook);  // ✅ Handle Stripe webhook

router.get("/payment_success", paymentsController.paymentSuccess);  // ✅ Payment success page
router.get("/payment_cancel", paymentsController.paymentCancel);  // ✅ Payment cancel page

router.get("/verify-email", paymentsController.verifyEmail);  // ✅ Verify email token

module.exports = router;
