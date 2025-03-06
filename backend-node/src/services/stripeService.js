const stripe = require("../utils/stripeClient");
const supabase = require("../config/supabaseClient");
const config = require("../config/env");

// ✅ Create Stripe Checkout Session
exports.createCheckoutSession = async (email, subscriptionPlan, chatSessionId) => {
  const user = await supabase.from("user_profiles").select("id").eq("email", email).single();
  if (!user.data) throw new Error("User not found with this email.");

  const userId = user.data.id;
  const plans = {
    monthly_no_offer: "price_1QhXfxDi1nqWbBYc76q14cWL",
    monthly_3mo_discount: "price_1QhdvrDi1nqWbBYcWOcfXTRJ",
    annual_free_week: "price_1QhdyFDi1nqWbBYcdzAdZ7lE",
    annual_further_discount: "price_1Qhe01Di1nqWbBYcixjWCokH",
  };

  const priceId = plans[subscriptionPlan];
  if (!priceId) throw new Error("Invalid subscription plan.");

  const stripeSession = await stripe.checkout.sessions.create({
    payment_method_types: ["card"],
    mode: "subscription",
    line_items: [{ price: priceId, quantity: 1 }],
    customer_email: email,
    success_url: `https://linkbooksai.com/payment_success?session_id={CHECKOUT_SESSION_ID}&chat_session_id=${chatSessionId || ""}`,
    cancel_url: `https://linkbooksai.com/payment_cancel?chat_session_id=${chatSessionId || ""}`,
    metadata: { userId, subscriptionPlan, chatSessionId },
  });

  return stripeSession.url;
};

// ✅ Handle Stripe Webhook Events
exports.handleWebhook = async (req) => {
  const sigHeader = req.headers["stripe-signature"];
  const event = stripe.webhooks.constructEvent(req.rawBody, sigHeader, config.STRIPE_WEBHOOK_SECRET);

  switch (event.type) {
    case "checkout.session.completed":
      await this.handleCheckoutCompleted(event.data.object);
      break;
    case "invoice.payment_succeeded":
      await this.handleInvoicePaid(event.data.object);
      break;
    case "customer.subscription.updated":
      await this.handleSubscriptionUpdated(event.data.object);
      break;
    default:
      console.log(`Unhandled event type: ${event.type}`);
  }

  return { received: true };
};

// ✅ Handle Successful Checkout
exports.handleCheckoutCompleted = async (session) => {
  await supabase.from("user_profiles").update({ subscription_status: "active" }).eq("email", session.customer_email);
};

// ✅ Handle Successful Invoice Payment
exports.handleInvoicePaid = async (invoice) => {
  await supabase.from("user_profiles").update({ subscription_status: "active" }).eq("customer_id", invoice.customer);
};

// ✅ Handle Subscription Updates
exports.handleSubscriptionUpdated = async (subscription) => {
  await supabase.from("user_profiles").update({
    subscription_status: subscription.status,
    subscription_id: subscription.id,
  }).eq("customer_id", subscription.customer);
};
