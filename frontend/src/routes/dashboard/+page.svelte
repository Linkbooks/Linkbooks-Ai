<script lang="ts">
	import { onMount } from 'svelte';
	import { writable } from 'svelte/store';

	const BACKEND_URL = import.meta.env.VITE_PUBLIC_BACKEND_URL || "http://localhost:3000";

	// ✅ Reactive stores for dashboard data
	export const quickbooksConnected = writable<boolean>(false);
	export const chatGPTSessions = writable<{ chatSessionId: string; createdAt: string; expiry: string }[]>([]);
	export const sessionToken = writable<string | null>(null);
	export const errorMessage = writable<string | null>(null);
	export const whatElseModal = writable(false);

	// ✅ Fetch Dashboard Data (QuickBooks Status + ChatGPT Sessions)
	async function fetchDashboardData() {
		try {
			const response = await fetch(`${BACKEND_URL}/dashboard/api/dashboard-data`, {
				method: "GET",
				credentials: "include"
			});

			if (!response.ok) {
				throw new Error(`Server responded with ${response.status}`);
			}

			const data = await response.json();

			// ✅ Update state with fetched data
			quickbooksConnected.set(!data.quickbooks_login_needed);
			chatGPTSessions.set(data.chatgpt_sessions || []);
			sessionToken.set(data.session_token || null);

			console.log("✅ Dashboard data loaded:", data);
		} catch (error) {
			console.error("❌ Error fetching dashboard data:", error);
			errorMessage.set("Failed to load dashboard data.");
		}
	}

	// ✅ Check authentication status before loading the dashboard
	onMount(async () => {
		try {
			const res = await fetch(`${BACKEND_URL}/auth/status`, { credentials: "include" });
			const data = await res.json();

			if (data.logged_in) {
				sessionToken.set(data.session_token);
				await fetchDashboardData(); // ✅ Fetch QuickBooks & ChatGPT session info
			} else {
				window.location.href = "/auth/login"; // 🔄 Redirect if not logged in
			}
		} catch (error) {
			console.error("❌ Error checking auth status:", error);
			window.location.href = "/auth/login";
		}
	});

	// ✅ "What Else Can I Do?" Modal Functions
	function openWhatElseModal() {
		whatElseModal.set(true);
	}
	function closeWhatElseModal() {
		whatElseModal.set(false);
	}

	// ✅ Placeholder function for "List Available Reports"
	function fetchReports() {
		console.log("📊 Fetching reports...");
		alert("Fetching available reports... (Functionality to be implemented)");
	}
</script>

<!-- ✅ Dashboard Page -->
<div class="dashboard-container">
	<header>
		<img src="/logo.png" alt="App Logo" class="logo">
		<h1>Linkbooks Ai</h1>
	</header>

	<div class="divider"></div>
	<h2 class="dashboard-title">Dashboard</h2>

	<!-- ✅ QuickBooks Connection Status -->
	{#if $quickbooksConnected}
		<div class="alert success">
			<strong>✅ QuickBooks Connected!</strong>
			<p>You are successfully connected to QuickBooks.</p>
		</div>
	{:else}
		<div class="alert warning">
			<strong>⚠️ QuickBooks not connected.</strong>
			<p>You need to log in with QuickBooks to access your data.</p>
			<!-- ✅ Added QuickBooks Login Button -->
			<a href={`${BACKEND_URL}/quickbooks-login`} class="button">🔗 Log in with QuickBooks</a>
		</div>
	{/if}

	<!-- ✅ Active ChatGPT Sessions -->
	<div class="status-container">
		<h3>ChatGPT Sessions</h3>
		<p>Active Sessions: {$chatGPTSessions.length}</p>

		<ul>
			{#each $chatGPTSessions as session, i}
				<li>
					<strong>Session {i + 1}:</strong> {session.chatSessionId}
					(Created: {new Date(session.createdAt).toLocaleString()})
				</li>
			{:else}
				<li>No active ChatGPT sessions.</li>
			{/each}
		</ul>
	</div>

	<!-- ✅ Dashboard Actions -->
	<div class="button-container">
		<button on:click={fetchDashboardData}>📊 List Available Reports</button>
		<button on:click={openWhatElseModal}>🛠️ What else can I do?</button>
	</div>

	{#if $errorMessage}
		<p class="error-message">❌ {$errorMessage}</p>
	{/if}

	<!-- ✅ "What Else Can I Do?" Modal -->
	{#if $whatElseModal}
		<div class="modal">
			<div class="modal-content">
				<h2>What Else Can I Do?</h2>
				<ul>
					<li>Generate business insights</li>
					<li>Create detailed reports</li>
					<li>Connect to QuickBooks</li>
					<li>Use AI-powered chat</li>
				</ul>
				<button on:click={closeWhatElseModal}>Close</button>
			</div>
		</div>
	{/if}
</div>

<style>
	.dashboard-container {
		max-width: 690px;
		margin: auto;
		margin-top: 20px;
		padding: 20px;
		text-align: center;
	}
	.logo {
		max-width: 100px;
		margin: 0 auto 10px;
		display: block;
	}
	.divider {
		width: 80px;
		height: 2px;
		background-color: green;
		margin: 20px auto;
	}
	.alert {
		padding: 10px;
		border-radius: 5px;
		margin: 10px auto;
		max-width: 500px;
	}
	.success { background: #d4edda; color: #155724; }
	.warning { background: #fff3cd; color: #856404; }
	.button-container {
		margin: 20px 0;
		display: flex;
		justify-content: center;
		gap: 15px;
	}
	button, .button {
		background-color: #468763;
		color: white;
		border: none;
		padding: 10px 20px;
		border-radius: 5px;
		cursor: pointer;
		font-size: 16px;
		text-decoration: none;
		display: inline-block;
	}
	button:hover, .button:hover {
		background-color: #35694b;
	}
	.modal {
		position: fixed;
		top: 0;
		left: 0;
		width: 100%;
		height: 100%;
		background: rgba(0, 0, 0, 0.5);
		display: flex;
		justify-content: center;
		align-items: center;
	}
	.modal-content {
		background: white;
		padding: 20px;
		border-radius: 5px;
		text-align: center;
	}
</style>
