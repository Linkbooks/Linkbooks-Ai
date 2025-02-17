<script lang="ts">
    import { goto } from '$app/navigation';
    // Instead of exporting `user` and `error` directly, export `data`
    export let data: {
      user: { name: string; email: string; subscription_status: string } | null;
      error: string | null;
    };
  
    const { user, error } = data;
  </script>
  
  <div class="profile-container">
    <img src="/logo.png" alt="Linkbooks Logo" class="logo" />
    <h1>User Profile</h1>
  
    {#if error}
      <p class="error-message">❌ {error}</p>
    {:else if user}
      <div class="profile-info">
        <p><strong>Name:</strong> {user.name}</p>
        <p><strong>Email:</strong> {user.email}</p>
        <p><strong>Subscription Status:</strong> {user.subscription_status}</p>
      </div>
    {:else}
      <p>Loading...</p>
    {/if}
  
    <button on:click={() => goto('/dashboard')} class="button">
      Back to Dashboard
    </button>
  </div>
  
  <style>
    .profile-container {
      max-width: 600px;
      margin: auto;
      padding: 20px;
      text-align: center;
    }
    .logo {
      max-width: 100px;
      margin-bottom: 10px;
    }
    .profile-info {
      background: #f9f9f9;
      padding: 15px;
      border-radius: 5px;
      margin: 15px 0;
    }
    .button {
      background: #468763;
      color: white;
      padding: 10px 15px;
      border: none;
      cursor: pointer;
      border-radius: 5px;
      font-size: 1rem;
    }
    .button:hover {
      background: #3a7455;
    }
    .error-message {
      color: red;
    }
  </style>
  