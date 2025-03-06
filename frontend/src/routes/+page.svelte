<script lang="ts">
	import '../lib/styles/global.css';
	import { goto } from '$app/navigation';
</script>

<!-- ✅ Hero Section -->
<header class="navbar">
	<nav class="navbar-container flex items-center justify-between py-2">
		<div class="header-content flex items-center">
			<img src="/logo.png" alt="Linkbooks Ai Logo" class="logo" />
			<h1 class="text-header ml-2 text-xl font-bold text-gray-900">Linkbooks Ai</h1>
		</div>
		<div class="navbar-buttons">
			<button class="button" on:click={() => goto('/auth/login')}>Log In</button>
            <button class="button secondary" on:click={() => goto('/auth/signup')}>Sign Up</button>
		</div>
	</nav>
</header>

<div class="hero">
	<h1 class="title">AI-Powered Financial Insights</h1>
	<p class="subtitle">Seamlessly connect your business finances with AI-driven analytics.</p>
	<div class="button-container">
		<a href="/signup" class="button primary">Get Started</a>
		<a href="/learn-more" class="button secondary">Learn More</a>
	</div>
</div>

<!-- ✅ Dynamic Wave Background -->
<div class="wave-container">
	<svg viewBox="0 0 1440 320" preserveAspectRatio="none" class="wave">
		<path fill="#468763" fill-opacity="1">
			<animate
				attributeName="d"
				dur="8s"
				repeatCount="indefinite"
				values="
                    M0,200 C400,100 1040,300 1440,200 L1440,320 L0,320 Z;
                    M0,180 C600,250 800,150 1440,180 L1440,320 L0,320 Z;
                    M0,200 C400,100 1040,300 1440,200 L1440,320 L0,320 Z
                "
			/>
		</path>
	</svg>
	<h2 class="wave-header">Why Choose <span class="semi-strong">Linkbooks Ai</span> ?</h2>
</div>

<!-- ✅ Features Section -->
<section class="features">
	<div class="feature-grid">
		<div class="feature">
			<h3>📊 AI-Powered Insights</h3>
			<p>Receive accurate financial insights based on real-time data.</p>
		</div>
		<div class="feature">
			<h3>🔗 Seamless Integrations</h3>
			<p>Connect with QuickBooks and other financial tools effortlessly.</p>
		</div>
		<div class="feature">
			<h3>⚡ Lightning Fast</h3>
			<p>Experience rapid calculations and AI-powered automation.</p>
		</div>
	</div>
</section>

<style>
	/* Navbar Styles */
	.navbar {
		position: fixed;
		top: 0;
		left: 0;
		right: 0;
		width: 100vw;
		margin: 0;
		padding: 0;
		background: white;
		box-shadow: 0px 4px 6px rgba(0, 0, 0, 0.1);
		z-index: 1000;
	}

	.navbar-container {
		width: 100%;
		max-width: 100%;
		margin: 0 auto;
		padding-top: 8px;
		padding-bottom: 8px;
		background: none; /* Remove white background */
		box-shadow: none; /* Remove the global shadow */
	}

	.navbar-buttons {
		display: flex;
		gap: 10px;
		margin-top: 10px;
		margin-right: 36px; /* Remove any extra right margin */
		margin-left: auto; /* This pushes the buttons to the right in a flex container */
	}

	.logo {
		width: 60px; /* Adjust the size of the logo */
		height: auto;
		margin-left: 20px;
		display: block;
		margin: 0 20px 0 20px; /* Adjust horizontal margins as needed */
	}

	.header-content {
		margin-left: 5px; /* Move header content to the right */
	}

	.text-header {
		margin-left: 10px; /* Move text header to the right */
		font-weight: bold;
		color: #3a3a3a;
		box-shadow: none !important; /* ✅ Ensures inner elements have no shadow */
		background: transparent; /* ✅ Prevent any white backgrounds from creating an effect */
		align-self: center; /* Ensures it's centered as a flex item */
		line-height: 1; /* Adjusts extra spacing */
		position: relative;
		top: -2px; /* Adjust this value as needed */
	}

	/* Hero Styles */
	.hero {
		padding-top: 180px; /* increased to clear the navbar */
		text-align: center;
		padding-bottom: 0px; /* further reduced padding-bottom to move features section up */
	}

	.title {
		font-size: 3rem;
		font-weight: bold;
		margin-bottom: 15px;
	}

	.subtitle {
		font-size: 1.5rem;
		margin-bottom: 30px;
		color: #555;
	}

	.button-container {
		display: flex;
		gap: 15px;
		justify-content: center;
	}

	/* Wave Background */
	.wave-container {
		position: relative; /* changed to relative */
		margin-bottom: 0;
		width: 100%;
		overflow: hidden;
		line-height: 0;
		height: 200px; /* increased height to allow higher wave */
		text-align: center; /* center the text */
	}

	.wave {
		width: 100%;
		height: 100%;
	}

	.wave-header {
		position: absolute;
		top: 81%;
		left: 50%;
		transform: translate(-50%, -50%);
		color: white;
		font-size: 1.5rem; /* increased font size */
		font-weight: 600; /* made text bolder */
		margin-bottom: 30px; /* added more margin below */
	}

	.semi-strong {
		font-weight: 650; /* slightly stronger font weight */
	}

	/* Features Section */
	.features {
		padding: 10px 20px;
		margin-top: 15px;
		text-align: center;
	}

	.feature-grid {
		display: flex;
		flex-wrap: wrap;
		justify-content: center;
		gap: 20px;
        margin-bottom: 40px;
	}

	.feature {
		flex: 1 1 250px;
		background: white;
		padding: 20px;
		border-radius: 10px;
		box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
	}

	/* Add hover effect for login button */
	.button:hover {
		background-color: #333; /* Darker background color */
		color: #fff; /* White text color */
		cursor: pointer; /* Change cursor to pointer */
	}

	/* Specific styles for the login button */
	.navbar-buttons .button {
		transition: background-color 0.3s ease; /* Smooth transition */
	}

	/* Add hover effect for sign up button */
	.button.secondary:hover {
		background-color: #468763; /* Dark green background color */
		color: #fff; /* White text color */
		cursor: pointer; /* Change cursor to pointer */
	}
</style>
