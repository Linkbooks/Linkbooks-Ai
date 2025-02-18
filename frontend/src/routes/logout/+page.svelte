<script lang="ts">
	import { onMount } from 'svelte';
	import { writable } from 'svelte/store';
	import { goto } from '$app/navigation';

	// ✅ Backend URL
	const BACKEND_URL = import.meta.env.VITE_PUBLIC_BACKEND_URL || "http://localhost:5000";

	// ✅ Reactive stores for logout state
	const logoutMessage = writable("🔄 Logging you out...");
	const logoutSuccess = writable<boolean | null>(null);
	const isLoading = writable(true);

	// ✅ Call logout API in the background
	async function logoutUser() {
		try {
			const response = await fetch(`${BACKEND_URL}/logout`, {
				method: "POST",
				credentials: "include"
			});

			const data = await response.json();

			if (response.ok && data.success) {
				logoutMessage.set("✅ " + data.message);
				logoutSuccess.set(true);
			} else {
				logoutMessage.set("❌ " + data.message);
				logoutSuccess.set(false);
			}
		} catch (error) {
			console.error("❌ Error during logout:", error);
			logoutMessage.set("❌ An error occurred while logging out.");
			logoutSuccess.set(false);
		} finally {
			isLoading.set(false);
		}
	}

	// ✅ Run logout in the background as soon as page loads
	onMount(() => {
		setTimeout(logoutUser, 100); // Ensures page loads first before making the request
	});

	// ✅ Redirect to login
	function redirectToLogin() {
		goto("/login");
	}

	// ✅ Retry logout
	function retryLogout() {
		isLoading.set(true);
		logoutMessage.set("🔄 Retrying logout...");
		logoutUser();
	}
</script>

<!-- ✅ Logout Page UI -->
<div class="logout-page">
	<header>
		<a href="/" class="header-link">
			<img src="/logo.png" alt="App Logo" class="logo">
			<h1>Linkbooks Ai</h1>
		</a>
	</header>

	<main>
		<h1>{$logoutMessage}</h1>

		<!-- ✅ Show spinner while waiting -->
		{#if $isLoading}
			<div class="spinner"></div>
			<p>🔄 Please wait...</p>
		{/if}

		<!-- ✅ Logout Successful -->
		{#if $logoutSuccess === true}
			<p>If you wish to log back in, click below:</p>
			<div class="button-container">
				<a href="/login" class="button">Log In</a>
			</div>
		{/if}

		<!-- ❌ Logout Failed -->
		{#if $logoutSuccess === false}
			<p>Something went wrong. Try again later.</p>
			<div class="button-container">
				<button on:click={retryLogout} class="button retry">Retry Logout</button>
				<button on:click={redirectToLogin} class="button">Go to Login</button>
			</div>
		{/if}
	</main>

	<footer>
		<p>&copy; 2025 Linkbooks Ltd. All rights reserved.</p>
	</footer>
</div>

<style>
	.logout-page {
		max-width: 600px;
		margin: auto;
		padding: 20px;
		text-align: center;
		font-family: Arial, sans-serif;
	}
	.logo {
		max-width: 100px;
		margin: 10px auto;
		display: block;
	}
	.button {
		display: inline-block;
		margin-top: 20px;
		padding: 10px 20px;
		background-color: #468763;
		color: white;
		text-decoration: none;
		border-radius: 5px;
		border: none;
		cursor: pointer;
		font-size: 16px;
	}
	.button:hover {
		background-color: #35694b;
	}
	.retry {
		background-color: #ff5f5f;
	}
	.retry:hover {
		background-color: #d44;
	}
	.spinner {
		width: 40px;
		height: 40px;
		margin: 20px auto;
		border: 4px solid rgba(0, 0, 0, 0.1);
		border-top: 4px solid #468763;
		border-radius: 50%;
		animation: spin 1s linear infinite;
	}
	@keyframes spin {
		0% { transform: rotate(0deg); }
		100% { transform: rotate(360deg); }
	}
</style>
