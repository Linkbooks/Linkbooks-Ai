const { createClient } = require("@supabase/supabase-js");

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;

if (!SUPABASE_URL || !SUPABASE_KEY) {
  throw new Error("❌ Supabase URL or Key is missing. Check your environment variables.");
}

// ✅ Initialize Supabase Client
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);
console.log("✅ Supabase client initialized successfully.");

module.exports = supabase;
