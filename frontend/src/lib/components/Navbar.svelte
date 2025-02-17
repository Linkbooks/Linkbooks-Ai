<script lang="ts">
    import { goto } from '$app/navigation';
    import { User, LogOut, Settings } from 'lucide-svelte';
    import { onMount } from 'svelte';

    let showDropdown = false;

    function navigate(event: MouseEvent, path: string): void {
        event.preventDefault();
        goto(path); // This navigates the user to the profile page
    }

    function toggleDropdown(event: MouseEvent) {
        event.preventDefault();
        event.stopPropagation(); // Prevents closing dropdown immediately
        showDropdown = !showDropdown;
    }

    // Close dropdown when clicking outside
    onMount(() => {
        document.addEventListener('click', (event) => {
            const dropdown = document.getElementById("profile-dropdown");
            if (dropdown && !dropdown.contains(event.target as Node)) {
                showDropdown = false;
            }
        });
    });
</script>

<!-- ✅ Tailwind-powered Navbar -->
<nav class="fixed top-0 right-0 w-full bg-transparent flex justify-end p-4 z-50">
    <div class="flex items-center space-x-6">
        <!-- ✅ User Profile Dropdown -->
        <div class="relative">
            <button 
                class="text-gray-700 hover:text-green-600 transition focus:outline-none"
                on:click|preventDefault={toggleDropdown}
            >
                <User size="24" />
            </button>

            <!-- ✅ Dropdown Menu -->
            {#if showDropdown}
                <div id="profile-dropdown" class="absolute right-0 mt-2 w-40 bg-white shadow-lg rounded-lg border border-gray-200">
                    <a href="/profile" 
                       class="block px-4 py-2 text-gray-700 hover:bg-gray-100 flex items-center"
                       on:click={(e) => navigate(e, '/profile')}>
                        <User size="20" class="mr-2" /> Profile
                    </a>
                    <a href="/logout" 
                       class="block px-4 py-2 text-gray-700 hover:bg-gray-100 flex items-center"
                       on:click={(e) => navigate(e, '/logout')}>
                        <LogOut size="20" class="mr-2" /> Logout
                    </a>
                </div>
            {/if}
        </div>

        <!-- ✅ Settings Icon -->
        <a href="/settings" class="text-gray-700 hover:text-green-600 transition">
            <Settings size="24" />
        </a>
    </div>
</nav>

<style>
/* ✅ Custom styles if needed */
</style>
