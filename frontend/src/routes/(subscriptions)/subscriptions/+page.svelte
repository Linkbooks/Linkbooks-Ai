<script lang="ts">
	const API_URL = import.meta.env.VITE_PUBLIC_BACKEND_URL || 'http://localhost:5000';
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';

	// State variables
	let email: string = '';
	let chatSessionId: string = '';
	let userId: string = '';

	// On mount loading logic (update to load session data)
	onMount(() => {
		// TODO: Load email, chatSessionId, and userId from session or via an API call.
	});

	// Additional client-side logic (e.g., form handling)
	// Hide and show plan details based on the selected option.
	// This code can be placed inside onMount or as separate functions.
	onMount(() => {
		const form = document.getElementById('subscriptions-form');
		// Hide all plan details initially
		document.querySelectorAll('.plan-details').forEach((details) => {
			(details as HTMLElement).style.display = 'none';
		});

		// Show plan details when a radio is selected
		function handlePlanSelection(event: Event) {
			const selectedInput = event.target as HTMLInputElement;
			if (selectedInput.type === 'radio') {
				document.querySelectorAll('.plan-details').forEach((details) => {
					(details as HTMLElement).style.display = 'none';
				});
				const selectedDetailsId = selectedInput.value + '-details';
				const selectedDetails = document.getElementById(selectedDetailsId);
				if (selectedDetails) {
					selectedDetails.style.display = 'block';
				}
			}
		}
		form?.addEventListener('change', handlePlanSelection);

		// Handle form submission
		form?.addEventListener('submit', async (event: Event) => {
			event.preventDefault();
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
					body: JSON.stringify(data)
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
		});
	});
</script>

<main>
	<form id="subscriptions-form" class="form-container container">
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
				<div class="plan-details" id="monthly_3mo_discount-details">
					<p>
						<strong>Monthly Plan Terms:</strong> Get the first 3 months for just £5 per month (£15 total).
						After the 3-month period, your subscription will automatically renew at £10 per month unless
						cancelled.
					</p>
					<p>
						<strong>Commitment Period:</strong> This plan has a 3-month minimum commitment. Cancellations
						are not allowed during the first 3 months.
					</p>
					<p>
						<strong>Cancellation Policy:</strong> You can cancel anytime after the 3rd month begins to
						avoid being charged £10 when the renewal happens.
					</p>
					<a href="/terms-and-conditions" target="_blank">Read Terms and Conditions</a>
				</div>
				<div class="plan-details" id="monthly_no_offer-details">
					<p>
						<strong>No Offer Terms:</strong> Standard monthly plan at &pound;10/month, cancel anytime.
					</p>
					<a href="/terms-and-conditions" target="_blank">Read Terms and Conditions</a>
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
				<div class="plan-details" id="annual_free_week-details">
					<p>
						<strong>Free Week Offer Terms:</strong> Your subscription includes a 7-day free trial. After
						the trial, you will be billed &pound;60 for the year. You can cancel during the free week
						to avoid charges.
					</p>
					<a href="/terms-and-conditions" target="_blank">Read Terms and Conditions</a>
				</div>
				<div class="plan-details" id="annual_further_discount-details">
					<p>
						<strong>Further Discount Terms:</strong> Pay upfront &pound;55/year (save an extra &pound;5).
					</p>
					<a href="/terms-and-conditions" target="_blank">Read Terms and Conditions</a>
				</div>
			</div>
		</div>

		<!-- Submit Button -->
		<button type="submit" id="proceed-to-checkout" class="button">Proceed to Checkout</button>
	</form>
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
	.plan-details {
		display: none;
		margin-top: 10px;
	}
	.offer-options label {
		display: block;
		margin-bottom: 5px;
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
