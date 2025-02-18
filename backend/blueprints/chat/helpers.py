import logging, jwt, eventlet
from openai import AssistantEventHandler

from flask import request, jsonify, abort
from flask_socketio import emit

from jwt import ExpiredSignatureError, InvalidTokenError

from extensions import socketio, supabase, openai_client
from config import Config
from datetime import datetime, timedelta

# ----------- Config Variables --------------#
ASSISTANT_ID = Config.OPENAI_ASSISTANT_ID
SECRET_KEY = Config.SECRET_KEY

# ------------------------------------------#
#            Chat Stuff                     #
# ------------------------------------------#
class StreamHandler(AssistantEventHandler):
    """
    Handles streaming AI responses via WebSockets.
    """
    def __init__(self, thread_id):
        super().__init__()
        self.response_text = ""
        self.thread_id = thread_id  # Store thread ID to associate responses

    def on_text_created(self, text):
        print("\nAssistant:", end="", flush=True)

    def on_text_delta(self, delta, snapshot):
        if delta.value:
            self.response_text += delta.value
            print(delta.value, end="", flush=True)

            # 🔹 Send each chunk via WebSockets to the frontend
            socketio.emit('chat_response', {'thread_id': self.thread_id, 'data': delta.value})

    def on_tool_call_created(self, tool_call):
        print(f"\nAssistant used tool: {tool_call.type}")

    def on_tool_call_delta(self, delta, snapshot):
        if delta.type == "code_interpreter" and delta.code_interpreter.input:
            print(delta.code_interpreter.input, end="", flush=True)

    def get_response(self):
        return self.response_text


# ------------------------------------------#
#     Process and Stream Response          #
# ------------------------------------------#
def process_and_stream_response(user_id, user_message):
    print(f"🔄 Processing message for user {user_id}: {user_message}", flush=True)

    # ✅ Retrieve thread_id from Supabase
    thread_query = supabase.table("user_threads").select("thread_id").eq("user_id", user_id).execute()
    thread_id = thread_query.data[0]["thread_id"] if thread_query.data else None

    if not thread_id:
        print("🆕 Creating new chat thread...", flush=True)
        thread = openai_client.beta.threads.create()
        thread_id = thread.id
        supabase.table("user_threads").insert({"user_id": user_id, "thread_id": thread_id}).execute()

    print(f"🟢 Using thread_id: {thread_id} for user {user_id}", flush=True)

    # ✅ Add user message to the thread
    openai_client.beta.threads.messages.create(
        thread_id=thread_id,
        role="user",
        content=user_message
    )

    print(f"📩 Chat message added to thread {thread_id}, streaming response...", flush=True)

    # ✅ Stream response from OpenAI
    handler = StreamHandler(thread_id)

    try:
        with openai_client.beta.threads.runs.stream(
            thread_id=thread_id,
            assistant_id=ASSISTANT_ID,
            event_handler=handler
        ) as stream:
            for chunk in stream:
                if chunk.event == "text_delta":
                    print(f"📡 Sending to WebSocket: {chunk.data.delta.value} (Thread: {thread_id})", flush=True)

                    # ✅ Ensure `thread_id` is always sent
                    socketio.emit("chat_response", {
                        "thread_id": thread_id if thread_id else "UNKNOWN_THREAD",
                        "data": chunk.data.delta.value if chunk.data.delta.value else "[NO DATA]"
                }, namespace="/")


    except Exception as e:
        print(f"❌ [ERROR] Streaming error: {str(e)}", flush=True)
        socketio.emit("chat_response", {
            "thread_id": thread_id,
            "data": "[ERROR] An error occurred."
        })
    finally:
        print(f"✅ WebSocket: Sent [DONE] (Thread: {thread_id})", flush=True)
        socketio.emit("chat_response", {
            "thread_id": thread_id,
            "data": "[DONE]"
        })


# ------------------------------------------#
#          Socket.IO Event Handlers          #
# ------------------------------------------#
@socketio.on('connect')
def on_connect():
    print("✅ Client connected", flush=True)
    emit('chat_response', {'data': "Connected to WebSocket"})

@socketio.on('disconnect')
def on_disconnect():
    print("❌ Client disconnected", flush=True)


@socketio.on('chat_message')
def handle_chat_message(data):
    """
    Handles incoming WebSocket messages and streams OpenAI responses.
    """
    sid = request.sid  # Get WebSocket session ID
    session_token = data.get("session_token")
    user_message = data.get("message")

    if not session_token:
        emit("chat_response", {"error": "No session token provided"}, room=sid)
        return

    # ✅ Decode JWT token
    try:
        decoded = jwt.decode(session_token, SECRET_KEY, algorithms=["HS256"])
        user_id = decoded.get("user_id")
    except (ExpiredSignatureError, InvalidTokenError) as e:
        emit("chat_response", {"error": "Invalid session token"}, room=sid)
        return

    # ✅ Retrieve or create thread_id
    thread_query = supabase.table("user_threads").select("thread_id").eq("user_id", user_id).execute()
    thread_id = thread_query.data[0]["thread_id"] if thread_query.data else None

    if not thread_id:
        thread = openai_client.beta.threads.create()
        thread_id = thread.id
        supabase.table("user_threads").insert({"user_id": user_id, "thread_id": thread_id}).execute()

    # ✅ Add user message to OpenAI thread
    openai_client.beta.threads.messages.create(
        thread_id=thread_id,
        role="user",
        content=user_message
    )

    # ✅ Stream response from OpenAI
    print(f"📡 Streaming response from OpenAI (Thread: {thread_id})")
    
    stream = openai_client.beta.threads.runs.create(
        thread_id=thread_id,
        assistant_id=ASSISTANT_ID,
        stream=True
    )

    for event in stream:
        if event.event == "thread.message.delta":
            chunk = event.data.delta.content[0].text.value
            socketio.emit("chat_response", {"thread_id": thread_id, "data": chunk}, room=sid)
            eventlet.sleep(0)  # ✅ Prevent blocking

    # ✅ Signal completion
    socketio.emit("chat_response", {"thread_id": thread_id, "data": "[DONE]"}, room=sid)


# ✅ Verify Assistant Configuration
try:
    assistant = openai_client.beta.assistants.retrieve(ASSISTANT_ID)
    logging.info(f"✅ Assistant Loaded: {assistant.name} ({ASSISTANT_ID})")
except Exception as e:
    logging.error(f"❌ Error retrieving assistant: {str(e)}")
    
# ✅ Update Assistant Instructions
assistant = openai_client.beta.assistants.update(
    assistant_id=ASSISTANT_ID,
    instructions=(
        "You are an AI assistant that helps users with QuickBooks transactions and invoices. "
        "You should remember previous interactions within a thread and provide context-aware responses. "
        "If a user asks follow-up questions, ensure you refer to previous discussions in the same thread."
    )
)