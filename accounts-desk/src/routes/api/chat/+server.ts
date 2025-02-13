import { json } from "@sveltejs/kit";
import type { RequestHandler } from '@sveltejs/kit';

// ✅ Ensure this is correctly structured for streaming
export const POST: RequestHandler = async ({ request }) => {
  try {
    const { message } = await request.json();
    const cookie = request.headers.get("cookie") || "";

    // ✅ Use fetch with streaming support
    const response = await fetch("http://localhost:5000/api/chat", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Cookie": cookie
      },
      body: JSON.stringify({ message }),
    });

    if (!response.ok) {
      console.error("❌ Backend error:", response.status, await response.text());
      return new Response(
        JSON.stringify({ error: `Backend error: ${response.statusText}` }),
        { status: response.status }
      );
    }

    // ✅ Ensure it's an SSE stream, not JSON
    const stream = new ReadableStream({
      async start(controller) {
        const reader = response.body?.getReader();
        if (!reader) {
          console.error("❌ No readable stream from backend.");
          controller.close();
          return;
        }

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          controller.enqueue(value);
        }
        controller.close();
      }
    });

    return new Response(stream, {
      headers: { "Content-Type": "text/event-stream" }
    });

  } catch (error) {
    console.error("❌ Error in API:", error);
    return json({ error: "Failed to connect to AI" }, { status: 500 });
  }
};
