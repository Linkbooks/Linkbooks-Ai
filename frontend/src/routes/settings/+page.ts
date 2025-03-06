import type { PageLoad } from './$types';

const BACKEND_URL = import.meta.env.VITE_PUBLIC_BACKEND_URL || "http://localhost:3000";

export const load: PageLoad = async ({ url, fetch }) => {
    console.log('Loading settings page...');
    try {
        const settingsType = url.searchParams.get('type') || 'general';
        const response = await fetch(`${BACKEND_URL}/user/settings?type=${settingsType}`, {
            method: "GET",
            credentials: "include"
        });

        if (!response.ok) {
            return { error: `Server responded with ${response.status}`, settingsType };
        }

        return { settingsType, error: null };
    } catch (error) {
        console.error("❌ Error loading settings:", error);
        return { error: "Failed to load settings.", settingsType: 'general' };
    }
};
