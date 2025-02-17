import type { PageLoad } from './$types';

const BACKEND_URL = import.meta.env.VITE_PUBLIC_BACKEND_URL || "http://localhost:5000";

export const load: PageLoad = async ({ fetch }) => {
    console.log('Loading user profile...');
    try {
        const response = await fetch(`${BACKEND_URL}/user_profile`, {
            method: "GET",
            credentials: "include"
        });

        if (!response.ok) {
            return { user: null, error: `Server responded with ${response.status}` };
        }

        const user = await response.json();

        // Check if there is any error in the user response
        if (!user || user.error) {
            return { user: null, error: user?.error || "Failed to load user profile." };
        }

        return { user, error: null };
    } catch (error) {
        console.error("❌ Error fetching user profile:", error);
        return { user: null, error: "Failed to load user profile." };
    }


    
};

