<script lang="ts">
	const API_URL = import.meta.env.VITE_PUBLIC_BACKEND_URL || 'http://localhost:3000';

	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import { get } from 'svelte/store';
	import { Eye, EyeOff } from 'lucide-svelte/icons'; // ✅ Correct import
	import '$lib/styles/global.css';

	let email = '';
	let password = '';
	let chatSessionId = '';
	let errorMessage = '';
	let loading = false;
	let passwordVisible = false; // ✅ Toggle for password visibility

	onMount(() => {
		const urlParams = new URLSearchParams(window.location.search);
		chatSessionId = urlParams.get('chatSessionId') || '';
	});

	async function handleSubmit(event: Event) {
		event.preventDefault();
		loading = true;
		errorMessage = '';

		try {
			const response = await fetch(`${API_URL}/auth/login`, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json'
				},
				credentials: 'include', // ✅ Ensures cookies are sent and received
				body: JSON.stringify({ email, password, chatSessionId })
			});

			const result = await response.json();
			loading = false;

			if (response.ok) {
				console.log('✅ Login successful!', result);
				localStorage.setItem('session_token', result.session_token); // ✅ Store session token for tracking

				// ✅ Check authentication status before redirecting
				const statusResponse = await fetch(`${API_URL}/auth/status`, { credentials: 'include' });
				const status = await statusResponse.json();

				if (status.logged_in) {
					goto('/dashboard'); // ✅ Redirect only if authentication is confirmed
				} else {
					errorMessage = 'Login successful, but session not established.';
				}
			} else {
				errorMessage = result.error_message || 'An unexpected error occurred. Please try again.';
			}
		} catch (error) {
			console.error('❌ Login error:', error);
			errorMessage = 'A network error occurred. Please try again.';
			loading = false;
		}
	}
</script>

<main class="login-page">
	<img src="/logo.png" alt="App Logo" class="logo" />
	<header>
		<a href="/" class="header-link">
			<h1>Linkbooks Ai</h1>
		</a>
		<p>Welcome back! Please log in to your account.</p>
	</header>

	<div class="form-container container">
		<h3>Log In</h3>
		{#if errorMessage}
			<div class="error-message">{errorMessage}</div>
		{/if}
		<form on:submit={handleSubmit}>
			<input type="hidden" name="chatSessionId" value={chatSessionId} />

			<!-- Email Input -->
			<div class="input-group">
				<label for="email">Email:</label>
				<input
					type="email"
					id="email"
					bind:value={email}
					required
					class="input-field"
					aria-label="Email address"
					title="Enter your email address here"
				/>
			</div>

			<!-- Password Input with Eye Toggle -->
			<div class="input-group">
				<label for="password">Password:</label>
				<div class="password-wrapper">
					<input
						type={passwordVisible ? 'text' : 'password'}
						id="password"
						bind:value={password}
						required
						class="input-field"
						aria-label="Password"
						title="Password must be at least 6 characters"
					/>
					<button
						type="button"
						class="password-toggle"
						aria-label="Toggle Password Visibility"
						on:click={() => (passwordVisible = !passwordVisible)}
					>
						{#if passwordVisible}
							<EyeOff size={22} strokeWidth={1.5} />
						{:else}
							<Eye size={22} strokeWidth={1.5} />
						{/if}
					</button>
				</div>
				<span class="tooltip-icon" title="Password must be at least 6 characters">ℹ️</span>
			</div>

			<!-- Submit Button -->
			<div class="button-container">
				<button
					type="submit"
					class="button primary"
					aria-label="Log in to your account"
					disabled={loading}>Log In</button
				>
				{#if loading}
					<span class="loading-spinner">⏳</span>
				{/if}
			</div>
		</form>

		<div id="progressive-forgot-password" class="progressive-forgot-password">
			<a href="/forgot-password" class="link">Forgot Password?</a>
		</div>

		<p class="form-note">
			Don't have an account?
			<a href="/auth/signup?chat_session_id={chatSessionId}" class="link">Create one</a>
		</p>
	</div>

	<div class="navigation">
		<a href="/" class="button secondary">Back to Homepage</a>
	</div>
</main>

<style>
	.password-wrapper {
		position: relative;
		display: flex;
		align-items: center;
		width: 100%;
	}

	.input-field {
		width: 100%;
		padding: 10px;
		border: 1px solid #ccc;
		border-radius: 6px;
	}

	.password-toggle {
		position: absolute;
		right: 10px;
		background: none;
		border: none;
		cursor: pointer;
		padding: 5px;
		display: flex;
		align-items: center;
		justify-content: center;
		color: #6c757d;
		transition: color 0.2s ease-in-out;
	}

	.password-toggle:hover {
		color: #333;
	}

	/* Style for the tooltip */
	.tooltip-icon {
		cursor: help;
		margin-left: 5px;
	}

	.loading-spinner {
		margin-left: 10px;
	}

	.button-container {
		display: flex;
		justify-content: center;
		align-items: center;
		width: 100%;
	}
</style>
