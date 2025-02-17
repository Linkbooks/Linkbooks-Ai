from .helpers import process_and_stream_response, StreamHandler
from extensions import socketio, supabase
from flask import Blueprint, request, jsonify, redirect, send_from_directory

chat_bp = Blueprint('chat', __name__, url_prefix='/chat')