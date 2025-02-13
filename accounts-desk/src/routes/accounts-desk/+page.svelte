<script lang="ts">
	import { onMount } from 'svelte';
	import { io, Socket } from 'socket.io-client';
	import { writable } from 'svelte/store';

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

			// ✅ Ensure Svelte properly updates the UI state
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

		const messageData = { session_token: sessionToken, message: userInput };

		console.log('📤 Sending message:', messageData); // ✅ Debugging log

		// ✅ Emit chat message with session token
		socket.emit('chat_message', messageData);

		// ✅ Add user's message to UI immediately
		messages.update((msgs) => [...msgs, { role: 'user', content: userInput }]);
		userInput = '';
		loading = true;
	}
</script>

<!-- ✅ Show WebSocket Connection Status -->
<p>WebSocket Status: {isConnected ? '🟢 Connected' : '🔴 Disconnected'}</p>

<div class="chat-container">
	<h2>💬 Linkbooks AI Desk</h2>

	<div class="messages">
		{#each $messages as msg}
			<div class="message {msg.role}">
				<strong>{msg.role === 'user' ? 'You' : msg.role === 'assistant' ? 'AI' : 'System'}:</strong>
				<div class="message-content" data-message="true">
					{@html msg.content}
				</div>
			</div>
		{/each}
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
		max-width: 600px;
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
		margin-bottom: 8px;
		white-space: pre-wrap;
		line-height: 1.4;
	}

	/* User & Assistant Message Styling */
	.user {
		background: #007bff;
		color: white;
		text-align: right;
		border-radius: 15px 15px 0 15px;
	}

	.assistant {
		background: #e0e0e0;
		border-radius: 15px 15px 15px 0;
	}

	/* Styling for Converted Markdown */
	:global(.message-content) {
		display: block;
		width: 100%;
		overflow-wrap: break-word;
		line-height: 1.55;
		padding: 6px 0;
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
		margin-top: 4px;
		margin-bottom: -24px;
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
		margin-top: -3px;
		margin-bottom: -12px;
	}
	:global(.message-content ul) {
		list-style-type: disc;
	}
	:global(.message-content ol) {
		list-style-type: decimal;
	}
	:global(.message-content li) {
		margin-bottom: -10px;
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
		background: #007bff;
		color: white;
		cursor: pointer;
	}
	button:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}
</style>
