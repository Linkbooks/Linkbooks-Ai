import { json } from "@sveltejs/kit";

export async function POST({ request }) {
  try {
    const { message } = await request.json();
    const cookie = request.headers.get("cookie") || "";

    console.log("🔄 Sending message to backend:", message);

    const response = await fetch("http://localhost:5000/chat", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Cookie": cookie // Forward the cookie to the backend
      },
      body: JSON.stringify({ message }),
    });

    console.log("✅ Backend responded with status:", response.status);

    if (response.status === 401) {
      return json({ error: "Unauthorized: Please log in again." }, { status: 401 });
    }

    const data = await response.json();
    
    console.log("📩 Backend Response:", data);

    if (!data.response) {
      return json({ reply: "No valid response from AI." });
    }

    return json({ reply: data.response });

  } catch (error) {
    console.error("❌ Error in API:", error);
    return json({ error: "Failed to connect to AI" }, { status: 500 });
  }
}
