<script lang="ts">
	import { onMount } from 'svelte';

	interface Message {
		role: string;
		content: string;
	}

	let messages: Message[] = [];
	let userInput: string = '';
	let loading: boolean = false;

	async function sendMessage() {
		if (!userInput.trim()) return;

		// ✅ Add user message to UI
		messages = [...messages, { role: 'user', content: userInput }];
		const input = userInput;
		userInput = '';
		loading = true;

		try {
			const response = await fetch('/api/chat', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				credentials: 'include',
				body: JSON.stringify({ message: input })
			});

			// ✅ Handle streaming response
			if (!response.body) {
				console.error("No response body");
				loading = false;
				return;
			}

			const reader = response.body.getReader();
			const decoder = new TextDecoder();
			let assistantMessage = { role: 'assistant', content: "" };
			messages = [...messages, assistantMessage];

			let streamedResponse = "";

			while (true) {
				const { value, done } = await reader.read();
				if (done) break;

				streamedResponse += decoder.decode(value, { stream: true });

				// ✅ Split streamed response into individual message chunks
				const chunks = streamedResponse.split("\n\n");

				// ✅ Extract last valid message chunk
				const lastChunk = chunks[chunks.length - 2]; // Last complete message

				if (lastChunk?.startsWith("data:")) {
					const content = lastChunk.replace("data:", "").trim();
					assistantMessage.content += content;
					messages = [...messages]; // ✅ Force reactivity update
				}
			}
		} catch (error) {
			console.error('Error:', error);
		}

		loading = false;
	}
</script>

<div class="chat-container">
	<h2>💬 Linkbooks AI Desk</h2>

	<div class="messages">
		{#each messages as msg}
			<div class="message {msg.role}">
				<strong>{msg.role === 'user' ? 'You' : 'AI'}:</strong>
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
	<button on:click={sendMessage} disabled={loading}>Send</button>
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

	/* Global Nested Lists */
	:global(.message-content ul ul),
	:global(.message-content ol ol) {
		margin-top: 4px;
		margin-bottom: 4px;
		padding-left: 18px;
	}

	/* Global Inline Formatting */
	:global(.message-content strong) {
		font-weight: bold;
	}
	:global(.message-content em) {
		font-style: italic;
	}
	:global(.message-content code) {
		font-family: monospace;
		background: #f4f4f4;
		padding: 3px 5px;
		border-radius: 4px;
		font-size: 0.9em;
	}

	/* Global Block Code */
	:global(.message-content pre) {
		background: #272822;
		color: #f8f8f2;
		padding: 12px;
		border-radius: 5px;
		overflow-x: auto;
		font-family: monospace;
		font-size: 0.95em;
	}

	/* Global Links */
	:global(.message-content a) {
		color: #007bff;
		text-decoration: none;
	}
	:global(.message-content a:hover) {
		text-decoration: underline;
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
