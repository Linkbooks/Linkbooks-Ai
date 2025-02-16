<script lang="ts">
	import { onMount } from 'svelte';
	import { io, Socket } from 'socket.io-client';
	import { writable } from 'svelte/store';
	import { marked } from 'marked';
	import DOMPurify from 'dompurify';

	// ✅ Define message structure
	interface Message {
		role: string;
		content: string;
	}

	// ✅ Create store for chat messages
	export const messages = writable<Message[]>([]);
	let userInput = '';
	let loading = false;
	let socket: Socket;
	let isConnected = false;
	let sessionToken: string | null = null;
	let chatContainer: HTMLDivElement | null = null;

	// ✅ Auto-scroll function
	function autoScroll() {
		setTimeout(() => {
			if (chatContainer) {
				chatContainer.scrollTop = chatContainer.scrollHeight;
			}
		}, 100);
	}

	// ✅ Watch for message updates & auto-scroll
	$: {
		$messages;
		autoScroll();
	}

	// ✅ Function to convert Markdown to HTML
	function renderMarkdown(content: string): string {
		// Ensure `marked.parse()` is treated as synchronous
		const parsed = marked.parse(content) as string;
		let sanitized = DOMPurify.sanitize(parsed);

		// Insert a line break for <strong> with a colon
		sanitized = sanitized.replace(/(<strong>[^<]*?):([^<]*?<\/strong>)/g, '$1:</strong><br>$2');

		return sanitized;
	}

	onMount(async () => {
		console.log('🔄 Checking authentication session...');

		try {
			const response = await fetch('http://localhost:5000/auth/status', {
				method: 'GET',
				credentials: 'include' // ✅ Ensures cookies are sent
			});

			const data = await response.json();

			if (data.logged_in && data.session_token) {
				console.log('✅ Session token retrieved:', data.session_token);
				localStorage.setItem('session_token', data.session_token);
				sessionToken = data.session_token;
			} else {
				console.warn('❌ Not logged in, redirecting...');
				window.location.href = 'http://localhost:5000/login';
			}
		} catch (error) {
			console.error('❌ Error fetching auth status:', error);
		}

		// ✅ Ensure only ONE WebSocket connection
		socket = io('http://localhost:5000', {
			transports: ['websocket', 'polling'], // ✅ Allow both WebSockets & Polling
			withCredentials: true,
			reconnection: true,
			reconnectionAttempts: 10,
			reconnectionDelay: 2000
		});

		// ✅ Handle WebSocket connection
		socket.on('connect', () => {
			console.log('✅ Connected to WebSocket!');
			isConnected = true;
		});

		socket.on('disconnect', () => {
			console.warn('❌ WebSocket Disconnected!');
			isConnected = false;
		});

		// ✅ Handle streaming responses
		socket.on('chat_response', (data: { thread_id?: string; data: string }) => {
			console.log('📩 WebSocket Response:', data);

			// ✅ Ensure thread_id exists before proceeding
			if (!data.thread_id) {
				console.warn('❌ Warning: Missing thread_id in response!', data);
				return;
			}

			// ✅ Stop loading animation on "[DONE]"
			if (data.data === '[DONE]') {
				console.log('✅ AI Response Completed');
				loading = false;
				return;
			}

			// ✅ Update messages store
			messages.update((msgs) => {
				// ✅ Append AI message if assistant already replied
				if (msgs.length > 0 && msgs[msgs.length - 1].role === 'assistant') {
					msgs[msgs.length - 1].content += data.data;
				} else {
					// ✅ Otherwise, add new assistant message
					msgs.push({ role: 'assistant', content: data.data });
				}
				return [...msgs];
			});
		});
	});

	function sendMessage() {
		if (!userInput.trim()) return;

		// ✅ Retrieve session token
		const sessionToken = localStorage.getItem('session_token');

		if (!sessionToken) {
			alert('No session token found! Please log in.');
			loading = false;
			return;
		}

		// ✅ Store the message in UI immediately
		messages.update((msgs) => [...msgs, { role: 'user', content: userInput }]);

		// ✅ Save user input before clearing
		const messageText = userInput;
		userInput = ''; // ✅ Clear input field immediately
		loading = true;

		// ✅ Send message to backend via WebSocket
		socket.emit('chat_message', { session_token: sessionToken, message: messageText });

		// ✅ Force auto-scroll to latest message
		autoScroll();
	}
</script>

<!-- ✅ Show WebSocket Connection Status -->
<p>WebSocket Status: {isConnected ? '🟢 Connected' : '🔴 Disconnected'}</p>

<div class="chat-container">
	<h2>💬 Linkbooks AI Desk</h2>

	<div class="messages" bind:this={chatContainer}>
		{#each $messages as msg}
			<div class="message {msg.role}">
				<strong>{msg.role === 'user' ? 'You' : msg.role === 'assistant' ? 'AI' : 'System'}:</strong>
				<div class="message-content" data-message="true">
					{@html renderMarkdown(msg.content)}
					<!-- ✅ Render Markdown -->
				</div>
			</div>
		{/each}
		
		{#if loading && (!$messages.length || $messages[$messages.length - 1].role !== 'assistant')}
			<div class="message assistant">
				<strong>AI:</strong>
				<div class="message-content loading">
					<span class="dot">.</span>
					<span class="dot">.</span>
					<span class="dot">.</span>
				</div>
			</div>
		{/if}
	</div>

	<input
		bind:value={userInput}
		placeholder="Ask me anything..."
		on:keypress={(e) => {
			if (e.key === 'Enter') {
				e.preventDefault();
				sendMessage();
			}
		}}
	/>
	<button on:click={sendMessage} disabled={loading || !isConnected}>Send</button>
</div>

<style>
	.chat-container {
		max-width: 750px;
		margin: auto;
		padding: 20px;
		font-family: Arial, sans-serif;
	}

	.messages {
		max-height: 400px;
		overflow-y: auto;
		border: 1px solid #ddd;
		padding: 10px;
		border-radius: 5px;
		background: #f9f9f9;
	}

	.message {
		padding: 10px;
		border-radius: 8px;
		margin-bottom: 10px !important;
		white-space: normal;
		line-height: 1.4;
	}

	/* User & Assistant Message Styling */
	.user {
		background: #468763;
		color: white;
		text-align: right;
		border-radius: 15px 15px 0 15px;
	}

	.assistant {
		background: #e0e0e0;
		border-radius: 15px 15px 15px 0;
	}

	/* Styling for Converted Markdown */

	/* ✅ Remove bottom margin from all block elements inside .message-content */
	:global(.message-content > *:last-child) {
		margin-bottom: 0 !important;
		padding-bottom: 0 !important;
	}

	:global(.message-content) {
		display: block;
		width: 100%;
		overflow-wrap: break-word;
		line-height: 1.55;
		padding: 6px 0;
		margin-bottom: 0 !important;
		padding-bottom: 0 !important;
	}

	:global(.message-content code) {
		font-family: monospace;
		background: #f4f4f4;
		padding: 3px 5px;
		border-radius: 4px;
		font-size: 0.9em;
	}

	:global(.message-content pre) {
		background: #272822;
		color: #f8f8f2;
		padding: 12px;
		border-radius: 5px;
		overflow-x: auto;
		font-family: monospace;
		font-size: 0.95em;
		margin-bottom: 0 !important; /* 🔹 Fix gap */
		padding-bottom: 0 !important; /* 🔹 Remove extra padding */
	}

	/* ✅ Ensure <p> tags inside Markdown do not add bottom margin */
	:global(.message-content p:last-child) {
		margin-bottom: 0 !important;
		padding-bottom: 0 !important;
	}

	/* Global Header Styling */
	:global(.message-content h1) {
		font-size: 1.8em;
		font-weight: bold;
		margin-top: 5px;
		margin-bottom: 4px;
	}
	:global(.message-content h2) {
		font-size: 1.5em;
		font-weight: bold;
		margin-top: 5px;
		margin-bottom: 2px;
	}
	:global(.message-content h3) {
		font-size: 1.3em;
		font-weight: bold;
		margin-top: 15px;
		margin-bottom: 10px;
		color: #333;
	}
	:global(.message-content h1:first-child),
	:global(.message-content h2:first-child),
	:global(.message-content h3:first-child) {
		margin-top: 5px;
	}

	/* Global Paragraph Styling */
	:global(.message-content p) {
		margin: 5px 0;
		display: block;
	}

	/* Global Lists Styling */
	:global(.message-content ul),
	:global(.message-content ol) {
		padding-left: 22px;
		margin: 4px 0;
		margin-top: 4px;
		margin-bottom: 4px;
	}
	:global(.message-content ul) {
		list-style-type: disc;
	}
	:global(.message-content ol) {
		list-style-type: decimal;
	}
	:global(.message-content li) {
		margin-bottom: 4px;
		display: list-item;
	}

	/* Inputs & Buttons */
	input,
	button {
		margin-top: 10px;
		width: 100%;
		padding: 10px;
		border: none;
		border-radius: 5px;
	}
	button {
		background: #468763;
		color: white;
		cursor: pointer;
	}
	button:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	/* Loading Animation */
	.loading {
		display: flex !important;
		gap: 4px;
		align-items: center;
		height: 24px;
	}

	.dot {
		animation: pulse 1.5s infinite;
		opacity: 0.5;
		font-size: 20px;
		line-height: 20px;
	}

	.dot:nth-child(2) {
		animation-delay: 0.5s;
	}

	.dot:nth-child(3) {
		animation-delay: 1s;
	}

	@keyframes pulse {
		0%, 100% {
			opacity: 0.3;
			transform: translateY(0);
		}
		50% {
			opacity: 1;
			transform: translateY(-2px); /* Reduced from -4px to -2px */
		}
	}
</style>
