const stripeService = require("../services/stripeService");
const emailVerificationService = require("../services/emailVerificationService");

// ✅ Get Subscription Page
exports.getSubscriptionPage = async (req, res) => {
  try {
    const { email, chatSessionId, userId } = req.query;

    if (!email) {
      return res.redirect(`/auth/signup?chatSessionId=${chatSessionId || ""}`);
    }

    const subscriptionStatus = await stripeService.getUserSubscriptionStatus(email);

    if (subscriptionStatus === "active") {
      return res.redirect("/dashboard");
    }

    return res.render("subscriptions", {
      email,
      chatSessionId,
      userId,
      message: subscriptionStatus === "pending" ? "Your payment is being processed." : "",
    });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// ✅ Create Subscription Checkout Session
exports.createSubscription = async (req, res) => {
  try {
    const { email, subscriptionPlan, chatSessionId } = req.body;
    if (!email || !subscriptionPlan) throw new Error("Email and subscription plan are required.");

    const checkoutUrl = await stripeService.createCheckoutSession(email, subscriptionPlan, chatSessionId);
    res.json({ checkoutUrl });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// ✅ Handle Stripe Webhook
exports.handleStripeWebhook = async (req, res) => {
  try {
    const event = await stripeService.handleWebhook(req);
    res.json(event);

  } catch (error) {
    res.status(400).json({ error: error.message });
  }
};

// ✅ Payment Success Page
exports.paymentSuccess = (req, res) => {
  const { session_id, chat_session_id } = req.query;
  if (!session_id) return res.status(400).send("Missing session ID");

  res.render("payment_success", { session_id, chat_session_id });
};

// ✅ Payment Cancel Page
exports.paymentCancel = (req, res) => {
  res.render("payment_cancel", { chat_session_id: req.query.chat_session_id });
};

// ✅ Verify Email Token
exports.verifyEmail = async (req, res) => {
  try {
    const { token } = req.query;
    const verificationResponse = await emailVerificationService.verifyEmailToken(token);
    res.json(verificationResponse);

  } catch (error) {
    res.status(400).json({ error: error.message });
  }
};
