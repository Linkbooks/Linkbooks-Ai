<script lang="ts">
    import { writable } from 'svelte/store';
    import '$lib/styles/global.css';
    import { goto } from '$app/navigation';


    // Store for selected settings category (defaults to 'general')
    let selectedCategory = writable('general');

    // Settings categories
    const categories = [
        { id: 'general', name: 'General Settings', icon: '⚙️' },
        { id: 'notifications', name: 'Notifications', icon: '🔔' },
        { id: 'privacy', name: 'Privacy & Security', icon: '🔒' },
        { id: 'integrations', name: 'Integrations', icon: '🔌' }
    ];

    // Switch category dynamically (no URL change)
    function switchCategory(categoryId: string) {
        selectedCategory.set(categoryId);
    }
</script>

<div class="settings-container">
    <img src="/logo.png" alt="Linkbooks Logo" class="logo" />
    <h1>Settings</h1>

    <div class="settings-layout">
        <!-- Settings Navigation -->
        <div class="settings-nav">
            {#each categories as category}
                <button
                    class="nav-button { $selectedCategory === category.id ? 'active' : '' }"
                    on:click={() => switchCategory(category.id)}
                >
                    <span class="icon">{category.icon}</span>
                    {category.name}
                </button>
            {/each}
        </div>
        

        <!-- Settings Content -->
        <div class="settings-content">
            {#if $selectedCategory === 'general'}
                <h2>General Settings</h2>
                <div class="setting-group">
                    <label>
                        Language
                        <select>
                            <option>English</option>
                            <option>Spanish</option>
                            <option>French</option>
                        </select>
                    </label>
                </div>
            {:else if $selectedCategory === 'notifications'}
                <h2>Notification Preferences</h2>
                <div class="setting-group">
                    <label class="checkbox-label">
                        <input type="checkbox" checked>
                        Email Notifications
                    </label>
                    <label class="checkbox-label">
                        <input type="checkbox">
                        Push Notifications
                    </label>
                </div>
            {:else if $selectedCategory === 'privacy'}
                <h2>Privacy & Security</h2>
                <div class="setting-group">
                    <button class="action-button">Change Password</button>
                    <button class="action-button">Two-Factor Authentication</button>
                </div>
            {:else if $selectedCategory === 'integrations'}
                <h2>Connected Services</h2>
                <div class="setting-group">
                    <div class="integration-item">
                        <span>QuickBooks</span>
                        <button class="action-button">Configure</button>
                    </div>
                </div>
            {/if}
        </div>
        
    </div>

    <button on:click={() => goto('/dashboard')} class="back-button">
        Back to Dashboard
    </button>
    
    
    
</div>

<style>
    .settings-container {
        max-width: 900px;
        margin: auto;
        padding: 20px;
        text-align: center;
    }

    .logo {
        max-width: 100px;
        margin-bottom: 20px;
    }

    .settings-layout {
        display: grid;
        grid-template-columns: 250px 1fr;
        gap: 20px;
        text-align: left;
        margin: 20px 0;
        background: #fff;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }

    .settings-nav {
        padding: 20px;
        border-right: 1px solid #eee;
    }

    .nav-button {
        display: flex;
        align-items: center;
        width: 100%;
        padding: 12px;
        margin: 4px 0;
        border: none;
        border-radius: 5px;
        background: none;
        cursor: pointer;
        text-align: left;
        font-size: 1rem;
    }

    .nav-button.active {
        background: #468763;
        color: white;
    }

    .nav-button:hover:not(.active) {
        background: #f0f0f0;
    }

    .icon {
        margin-right: 8px;
    }

    .settings-content {
        padding: 20px;
    }

    .setting-group {
        margin: 20px 0;
    }

    .setting-group label {
        display: block;
        margin: 10px 0;
    }

    .checkbox-label {
        display: flex;
        align-items: center;
        gap: 8px;
    }

    select {
        width: 200px;
        padding: 8px;
        border-radius: 4px;
        border: 1px solid #ddd;
    }

    .action-button {
        background: #468763;
        color: white;
        border: none;
        padding: 8px 16px;
        border-radius: 4px;
        cursor: pointer;
        margin: 5px 0;
    }

    .action-button:hover {
        background: #3a7455;
    }

    .integration-item {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 10px;
        border: 1px solid #eee;
        border-radius: 4px;
    }

    .back-button {
        background: #468763;
        color: white;
        border: none;
        padding: 10px 20px;
        border-radius: 5px;
        cursor: pointer;
        margin-top: 20px;
    }

    .back-button:hover {
        background: #3a7455;
    }

    @media (max-width: 768px) {
        .settings-layout {
            grid-template-columns: 1fr;
        }

        .settings-nav {
            border-right: none;
            border-bottom: 1px solid #eee;
        }
    }
</style>
