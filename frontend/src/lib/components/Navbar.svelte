<script lang="ts">
	import { goto } from '$app/navigation';
	import { User, LogOut, Settings } from 'lucide-svelte';
	import { onMount } from 'svelte';


    // ✅ Backend URL
    const BACKEND_URL = import.meta.env.VITE_PUBLIC_BACKEND_URL || 'http://localhost:5000';

    
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
			const dropdown = document.getElementById('profile-dropdown');
			if (dropdown && !dropdown.contains(event.target as Node)) {
				showDropdown = false;
			}
		});
	});

    async function logoutUser(event: MouseEvent) {
    event.preventDefault(); // Prevent default navigation behavior
    goto("/logout"); // ✅ Redirect to the logout page where API call happens
}


</script>

<!-- ✅ Tailwind-powered Navbar -->
<nav class="fixed right-0 top-0 z-50 flex w-full justify-end bg-transparent p-4">
	<div class="flex items-center space-x-6">
		<!-- ✅ User Profile Dropdown -->
		<div class="relative">
			<button
				class="text-gray-700 transition hover:text-green-600 focus:outline-none"
				on:click|preventDefault={toggleDropdown}
			>
				<User size="24" />
			</button>

			<!-- ✅ Dropdown Menu -->
			{#if showDropdown}
				<div
					id="profile-dropdown"
					class="absolute right-0 mt-2 w-40 rounded-lg border border-gray-200 bg-white shadow-lg"
				>
					<a
						href="/profile"
						class="block flex items-center px-4 py-2 text-gray-700 hover:bg-gray-100"
						on:click={(e) => navigate(e, '/profile')}
					>
						<User size="20" class="mr-2" /> Profile
					</a>
					<a
						href="/logout"
						class="block flex items-center px-4 py-2 text-gray-700 hover:bg-gray-100"
						on:click|preventDefault={logoutUser}>
						<LogOut size="20" class="mr-2" /> Logout
					</a>
				</div>
			{/if}
		</div>

		<!-- ✅ Settings Icon -->
		<a href="/settings" class="text-gray-700 transition hover:text-green-600">
			<Settings size="24" />
		</a>
	</div>
</nav>

<style>
	/* ✅ Custom styles if needed */
</style>
