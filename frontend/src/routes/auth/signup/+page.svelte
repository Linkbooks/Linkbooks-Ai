<script lang="ts">
    // Define the API URL from your environment variable.
    const API_URL = import.meta.env.VITE_PUBLIC_BACKEND_URL || 'http://localhost:5000';
  
    import { onMount } from 'svelte';
    import { goto } from '$app/navigation';
    import { Eye, EyeOff } from 'lucide-svelte/icons';
    import '$lib/styles/global.css';
  
    let email = '';
    let password = '';
    let confirmPassword = '';
    let name = '';
    let phone = '';
    let address = '';
    let chatSessionId = '';
    let errorMessage = '';
    let loading = false;
    let passwordVisible = false;
  
    onMount(() => {
      const urlParams = new URLSearchParams(window.location.search);
      chatSessionId = urlParams.get('chatSessionId') || '';
    });
  
    function isValidEmail(email: string): boolean {
      const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      return emailPattern.test(email);
    }
  
    function isValidPhone(phone: string): boolean {
      const phonePattern = /^\d+$/;
      return phonePattern.test(phone);
    }
  
    async function handleSubmit(event: Event) {
      event.preventDefault();
      loading = true;
  
      if (!isValidEmail(email)) {
        errorMessage = 'Please enter a valid email address.';
        loading = false;
        return;
      }
  
      if (!isValidPhone(phone)) {
        errorMessage = 'Please enter a valid phone number.';
        loading = false;
        return;
      }
  
      if (password !== confirmPassword) {
        errorMessage = 'Passwords do not match.';
        loading = false;
        return;
      }
  
      const response = await fetch(`${API_URL}/create-account`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        credentials: 'include', // Ensures cookies are sent and received
        body: new URLSearchParams({
          email,
          password,
          confirm_password: confirmPassword,
          name,
          phone,
          address,
          chat_session_id: chatSessionId
        })
      });
  
      const result = await response.json();
      loading = false;
  
      if (response.ok) {
        goto(result.redirect_url || '/payments/subscriptions');
      } else {
        errorMessage =
          result.error_message || 'An unexpected error occurred during signup. Please try again.';
      }
    }
  </script>
  
  <main class="signup-page">
    <img src="/logo.png" alt="App Logo" class="logo" />
    <header>
      <a href="/" class="header-link">
        <h1>Linkbooks Ai</h1>
      </a>
      <p>Create your account to get started.</p>
    </header>
  
    <div class="form-container container">
      <h3>Sign Up</h3>
      {#if errorMessage}
        <div class="error-message">{errorMessage}</div>
      {/if}
      <form on:submit={handleSubmit}>
        <!-- Hidden input with matching name -->
        <input type="hidden" name="chat_session_id" value={chatSessionId} />
  
        <!-- Name Input -->
        <div class="input-group">
          <label for="name">Full Name:</label>
          <input
            type="text"
            id="name"
            name="name"
            bind:value={name}
            required
            class="input-field"
            aria-label="Full Name"
            title="Enter your full name here" />
        </div>
  
        <!-- Email Input -->
        <div class="input-group">
          <label for="email">Email:</label>
          <input
            type="email"
            id="email"
            name="email"
            bind:value={email}
            required
            class="input-field"
            aria-label="Email address"
            title="Enter your email address here" />
        </div>
  
        <!-- Password Input with Eye Toggle -->
        <div class="input-group">
          <label for="password">Password:</label>
          <div class="password-wrapper">
            <input
              type={passwordVisible ? 'text' : 'password'}
              id="password"
              name="password"
              bind:value={password}
              required
              class="input-field"
              aria-label="Password"
              title="Password must be at least 6 characters" />
            <button
              type="button"
              class="password-toggle"
              aria-label="Toggle Password Visibility"
              on:click={() => (passwordVisible = !passwordVisible)}>
              {#if passwordVisible}
                <EyeOff size={22} strokeWidth={1.5} />
              {:else}
                <Eye size={22} strokeWidth={1.5} />
              {/if}
            </button>
          </div>
          <span class="tooltip-icon" title="Password must be at least 6 characters">ℹ️</span>
        </div>
  
        <!-- Confirm Password Input with Eye Toggle -->
        <div class="input-group">
          <label for="confirmPassword">Confirm Password:</label>
          <div class="password-wrapper">
            <input
              type={passwordVisible ? 'text' : 'password'}
              id="confirmPassword"
              name="confirm_password"
              bind:value={confirmPassword}
              required
              class="input-field"
              aria-label="Confirm Password"
              title="Re-enter your password" />
            <button
              type="button"
              class="password-toggle"
              aria-label="Toggle Password Visibility"
              on:click={() => (passwordVisible = !passwordVisible)}>
              {#if passwordVisible}
                <EyeOff size={22} strokeWidth={1.5} />
              {:else}
                <Eye size={22} strokeWidth={1.5} />
              {/if}
            </button>
          </div>
        </div>
  
        <!-- Phone Input -->
        <div class="input-group">
          <label for="phone">Phone Number:</label>
          <input
            type="tel"
            id="phone"
            name="phone"
            bind:value={phone}
            class="input-field"
            aria-label="Phone Number"
            title="Enter your phone number here" />
        </div>
  
        <!-- Address Input -->
        <div class="input-group">
          <label for="address">Address:</label>
          <textarea
            id="address"
            name="address"
            bind:value={address}
            rows="3"
            class="input-field"
            aria-label="Address"
            title="Enter your address here"></textarea>
        </div>
  
        <!-- Submit Button -->
        <div class="button-container">
          <button
            type="submit"
            class="button primary"
            aria-label="Create your account"
            disabled={loading}>Sign Up</button>
          {#if loading}
            <span class="loading-spinner">⏳</span>
          {/if}
        </div>
      </form>
  
      <p class="form-note">
        Already have an account?
        <a href="/auth/login?chat_session_id={chatSessionId}" class="link">Log in</a>
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
