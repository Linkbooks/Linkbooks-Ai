import { json } from "@sveltejs/kit";

const BACKEND_URL = import.meta.env.VITE_PUBLIC_BACKEND_URL || "http://localhost:5000";

export async function GET({ request }) {
    const cookie = request.headers.get("cookie") || "";

    try {
        const response = await fetch(`${BACKEND_URL}/dashboard`, {
            method: "GET",
            headers: {
                "Content-Type": "application/json",
                "Cookie": cookie
            },
            credentials: "include"
        });

        if (!response.ok) {
            throw new Error(`Flask API responded with ${response.status}`);
        }

        const data = await response.json();
        return json(data);
    } catch (error) {
        console.error("❌ Error fetching dashboard data:", error);
        return json({ error: "Failed to fetch dashboard data" }, { status: 500 });
    }
}
