<script lang="ts">
    import '$lib/styles/global.css';
    import Navbar from '$lib/components/Navbar.svelte';
	import Footer from '$lib/components/Footer.svelte';
    import { page } from '$app/stores';
    import { derived } from 'svelte/store';

    // ✅ Show navbar only on specific pages
    const showNavbar = derived(page, ($page) => {
        const path = $page.url.pathname;
        return path.startsWith('/dashboard') || 
               path.startsWith('/account') || 
               path.startsWith('/profile') || 
               path.startsWith('/settings');
    });
</script>

<div class="app-container">
    {#if $showNavbar}
        <Navbar />
    {/if}

    <main class="main-content">
        <slot />
    </main>

    <Footer />
</div>

<style>
    .app-container {
        display: flex;
        flex-direction: column;
        min-height: 100vh;
    }

    .main-content {
        flex: 1;
    }
</style>