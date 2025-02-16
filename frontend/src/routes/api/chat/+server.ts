import { json } from "@sveltejs/kit";
import type { RequestHandler } from '@sveltejs/kit';

// src/routes/api/chat/+server.ts

// Helper function to convert a Node stream to a Web ReadableStream
function nodeStreamToWebStream(nodeStream: any): ReadableStream<Uint8Array> {
  return new ReadableStream({
    start(controller) {
      nodeStream.on('data', (chunk: any) => {
        controller.enqueue(chunk);
      });
      nodeStream.on('end', () => {
        controller.close();
      });
      nodeStream.on('error', (err: any) => {
        controller.error(err);
      });
    }
  });
}

export const POST: RequestHandler = async ({ request }) => {
  try {
    const { message } = await request.json();
    const cookie = request.headers.get("cookie") || "";

    const response = await fetch("http://localhost:5000/chat", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Cookie": cookie
      },
      body: JSON.stringify({ message })
    });

    if (response.status === 401) {
      return new Response(
        JSON.stringify({ error: "Unauthorized: Please log in again." }),
        { status: 401 }
      );
    }

    // Check that response.body is not null.
    if (!response.body) {
      throw new Error("No response body");
    }

    // Determine if the response.body is a Web ReadableStream
    const stream = typeof response.body.getReader === "function"
      ? response.body
      : nodeStreamToWebStream(response.body);

    return new Response(stream, {
      headers: { "Content-Type": "text/event-stream" }
    });
    
  } catch (error: any) {
    console.error("❌ Error in API:", error);
    return new Response(
      JSON.stringify({ error: "Failed to connect to AI" }),
      { status: 500 }
    );
  }
};
