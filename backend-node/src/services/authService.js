const supabase = require("../config/supabaseClient");
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { generateSessionToken } = require('../utils/tokenHelper');

//Login Function
exports.login = async (email, password, chatSessionId) => {
  try {
    // ✅ Use Supabase Auth to verify user exists
    const { data: authData, error: authError } = await supabase.auth.signInWithPassword({
      email,
      password,
    });

    if (authError) {
      throw { status: 401, message: "Invalid email or password." };
    }

    const user_id = authData.user.id;

    // ✅ Fetch user profile from user_profiles
    const { data: profileData, error: profileError } = await supabase
      .from("user_profiles")
      .select("id, email")
      .eq("id", user_id)
      .single();

    if (!profileData) {
      throw { status: 404, message: "User profile not found." };
    }

    // ✅ Generate session token
    const token = generateSessionToken(user_id, email);

    return {
      session_token: token,
      chatSessionId,
      redirect_url: "/dashboard",
    };
  } catch (err) {
    console.error("❌ Login Error:", err);
    throw err.status ? err : { status: 500, message: "An unexpected error occurred." };
  }
};

//Logout Function
exports.logout = async (sessionToken) => {
  const decoded = jwt.verify(sessionToken, process.env.JWT_SECRET);
  const user_id = decoded.user_id;

  await supabase.from("quickbooks_tokens").delete().eq("user_id", user_id);
};

//Create Account Function
exports.createAccount = async (userData) => {
  const { email, password, name, phone, address } = userData;

  const { data: existingUsers } = await supabase.from("users").select("id").eq("email", email);
  if (existingUsers.length > 0) {
    throw { status: 400, message: "An account with this email already exists." };
  }

  const { data, error } = await supabase.auth.signUp({ email, password });

  if (error) {
    throw { status: 500, message: "Error creating account." };
  }

  const user_id = data.user.id;

  await supabase.from("user_profiles").insert({
    id: user_id,
    name,
    email,
    phone,
    address,
    subscription_status: "inactive",
    is_verified: false,
  });

  return { success: true, redirect_url: `/subscriptions?email=${email}` };
};
