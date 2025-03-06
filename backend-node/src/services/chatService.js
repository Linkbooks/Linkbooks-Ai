const supabase = require("../config/supabaseClient");
const openai = require("../config/openaiClient");
const { verifySessionToken } = require("../utils/tokenHelper");


// Process user message and stream response from OpenAI
exports.processAndStreamResponse = async (session_token, userMessage) => {
  try {
    const decoded = verifySessionToken(session_token);
    const user_id = decoded.user_id;

    // Retrieve existing chat thread or create a new one
    let { data: threads } = await supabase
      .from("user_threads")
      .select("thread_id")
      .eq("user_id", user_id);

    let thread_id = threads.length ? threads[0].thread_id : null;

    if (!thread_id) {
      console.log("🆕 Creating new chat thread...");
      const thread = await openai.beta.threads.create();
      thread_id = thread.id;
      await supabase.from("user_threads").insert({ user_id, thread_id });
    }

    console.log(`🟢 Using thread_id: ${thread_id} for user ${user_id}`);

    // Add user message to OpenAI thread
    await openai.beta.threads.messages.create({
      thread_id,
      role: "user",
      content: userMessage,
    });

    console.log(`📩 Chat message added to thread ${thread_id}, streaming response...`);

    return { success: true, thread_id };

  } catch (error) {
    console.error(`❌ Error processing chat message: ${error.message}`);
    throw error;
  }
};
