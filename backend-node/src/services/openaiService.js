const supabase = require("../config/supabaseClient");
const openaiClient = require("../utils/openaiClient");

// ✅ Fetch User Preferences
exports.getUserPreferences = async (chatSessionId) => {
  const { data } = await supabase
    .from("user_profiles")
    .select("personalization_note")
    .eq("chat_session_id", chatSessionId)
    .single();

  return { personalizationNote: data?.personalization_note || "No preferences set." };
};

// ✅ Update User Preferences
exports.updateUserPreferences = async (chatSessionId, personalizationNote) => {
  await supabase.from("user_profiles").update({ personalization_note: personalizationNote }).eq("chat_session_id", chatSessionId);
  return { message: "Preferences updated successfully." };
};

// ✅ Test OpenAI Connection
exports.testOpenAIConnection = async () => {
  const response = await openaiClient.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: "Hello, test connection." }],
    max_tokens: 50,
  });

  return { message: response.choices[0].message.content };
};

// ✅ Validate OpenAI API Key
exports.validateOpenAIKey = async () => {
  if (!openaiClient.api_key) throw new Error("OpenAI API key not loaded.");
  return { message: "OpenAI API key is valid." };
};
