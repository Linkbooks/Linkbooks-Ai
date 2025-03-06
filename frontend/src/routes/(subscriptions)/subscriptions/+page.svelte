<script lang="ts">
	const API_URL = import.meta.env.VITE_PUBLIC_BACKEND_URL || 'http://localhost:5000';
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';

	// State variables
	let email: string = '';
	let chatSessionId: string = '';
	let userId: string = '';
	let isLoadingSession = true; // Prevent form submission until session is loaded

	// Fetch session data from Flask on mount
	onMount(async () => {
	try {
		const response = await fetch(`${API_URL}/session`, { credentials: 'include' });
		const data = await response.json();

		if (response.ok) {
			email = data.email;  // ✅ Now fetched from backend
			userId = data.user_id;
			chatSessionId = data.chat_session_id;
		} else {
			console.error('Session Fetch Error:', data.error);
			alert('Session expired. Please log in again.');
			goto('/auth/login');
		}
	} catch (error) {
		console.error('Session Fetch Failed:', error);
		alert('Failed to load session. Please log in.');
		goto('/auth/login');
	} finally {
		isLoadingSession = false; // ✅ Ensure form only appears after session is loaded
	}
});


	// Handle form submission
	async function handleSubmit(event: Event) {
		event.preventDefault();
		
		// Prevent submission if session data is still loading
		if (isLoadingSession) {
			alert('Loading session data. Please wait...');
			return;
		}

		const selectedPlan = document.querySelector(
			'input[name="subscription-plan"]:checked'
		) as HTMLInputElement;

		if (!selectedPlan) {
			alert('Please select a subscription plan');
			return;
		}

		const data = {
			subscription_plan: selectedPlan.value,
			email: email,
			chat_session_id: chatSessionId,
			user_id: userId
		};

		try {
			const response = await fetch(`${API_URL}/subscriptions`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify(data),
				credentials: 'include' // Include session cookies
			});

			const result = await response.json();
			if (result.checkoutUrl) {
				window.location.href = result.checkoutUrl;
			} else {
				alert('Error creating checkout session');
			}
		} catch (error) {
			console.error('Error:', error);
			alert('Error creating checkout session');
		}
	}
</script>

<main>
	{#if isLoadingSession}
		<p>Loading session data...</p>
	{:else}
		<form id="subscriptions-form" class="form-container container" on:submit={handleSubmit}>
			<!-- Hidden inputs -->
			<input type="hidden" id="email" bind:value={email} />
			<input type="hidden" id="chat-session-id" bind:value={chatSessionId} />
			<input type="hidden" id="user-id" bind:value={userId} />

			<h2>Select Your Subscription Plan</h2>

			<div id="subscription-options" class="subscription-options">
				<!-- Monthly Plan Box -->
				<div class="plan-box" data-plan="monthly">
					<h3>Monthly Plan</h3>
					<p class="price">&pound;10/month</p>
					<div class="offers-section">
						<p><strong>Offers Included:</strong></p>
						<div class="offer-options">
							<label class="offer-label">
								<input type="radio" name="subscription-plan" value="monthly_3mo_discount" required />
								&pound;5/month for first 3 months
							</label>
							<label class="offer-label">
								<input type="radio" name="subscription-plan" value="monthly_no_offer" required />
								No offer: &pound;10/month, cancel anytime
							</label>
						</div>
					</div>
				</div>

				<!-- Annual Plan Box -->
				<div class="plan-box" data-plan="annual">
					<h3>Annual Plan</h3>
					<p class="price">&pound;5/month (billed &pound;60/year)</p>
					<div class="offers-section">
						<p><strong>Offers Included:</strong></p>
						<div class="offer-options">
							<label class="offer-label">
								<input type="radio" name="subscription-plan" value="annual_free_week" required />
								Free Week: Try for 7 days, then pay &pound;60/year
							</label>
							<label class="offer-label">
								<input
									type="radio"
									name="subscription-plan"
									value="annual_further_discount"
									required
								/>
								Further Discount: &pound;55/year (Save an extra &pound;5 if you pay upfront)
							</label>
						</div>
					</div>
				</div>
			</div>

			<!-- Submit Button -->
			<button type="submit" id="proceed-to-checkout" class="button">Proceed to Checkout</button>
		</form>
	{/if}
</main>

<style>
	/* Copy styles from your subscriptions HTML */
	.container {
		max-width: 800px;
		margin: 0 auto;
		padding: 20px;
	}
	.form-container {
		background: #fff;
		border-radius: 8px;
		padding: 20px;
		box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
	}
	h2 {
		text-align: center;
		margin-bottom: 20px;
	}
	.subscription-options {
		display: flex;
		flex-wrap: wrap;
		gap: 20px;
		justify-content: center;
	}
	.plan-box {
		border: 1px solid #ccc;
		border-radius: 8px;
		padding: 15px;
		flex: 1 1 300px;
	}
	.plan-box .price {
		font-size: 1.2em;
		font-weight: bold;
	}
	.button {
		display: inline-block;
		padding: 10px 15px;
		background-color: #468763;
		color: #fff;
		border: none;
		border-radius: 4px;
		text-align: center;
		cursor: pointer;
	}
	.button:hover {
		opacity: 0.9;
	}
</style>
