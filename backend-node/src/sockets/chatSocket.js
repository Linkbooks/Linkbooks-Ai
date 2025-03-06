const jwt = require("jsonwebtoken");
const supabase = require("../config/supabaseClient");
const openai = require("../config/openaiClient");

// Process user message and stream response from OpenAI
module.exports = (io) => {
  io.on("connection", (socket) => {
    console.log("✅ Client connected to WebSocket");

    socket.on("chat_message", async (data) => {
      try {
        const { session_token, message } = data;
        if (!session_token) {
          socket.emit("chat_response", { error: "No session token provided" });
          return;
        }

        const decoded = jwt.verify(session_token, process.env.JWT_SECRET);
        const user_id = decoded.user_id;

        let { data: threads } = await supabase
          .from("user_threads")
          .select("thread_id")
          .eq("user_id", user_id);

        let thread_id = threads.length ? threads[0].thread_id : null;

        if (!thread_id) {
          const thread = await openai.beta.threads.create();
          thread_id = thread.id;
          await supabase.from("user_threads").insert({ user_id, thread_id });
        }

        await openai.beta.threads.messages.create({
          thread_id,
          role: "user",
          content: message,
        });

        const stream = openai.beta.threads.runs.create({
          thread_id,
          assistant_id: process.env.OPENAI_ASSISTANT_ID,
          stream: true,
        });

        for await (const event of stream) {
          if (event.event === "thread.message.delta") {
            const chunk = event.data.delta.content[0].text.value;
            socket.emit("chat_response", { thread_id, data: chunk });
          }
        }

        socket.emit("chat_response", { thread_id, data: "[DONE]" });

      } catch (error) {
        console.error(`❌ WebSocket error: ${error.message}`);
        socket.emit("chat_response", { error: "An error occurred." });
      }
    });

    socket.on("disconnect", () => {
      console.log("❌ Client disconnected");
    });
  });
};
