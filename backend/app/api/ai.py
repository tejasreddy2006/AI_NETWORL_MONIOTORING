"""
NetGuard AI — AI Chat API Blueprint.

Exposes REST endpoints for conversational AI chat,
conversation history retrieval, and session management.
"""

from __future__ import annotations

from flask import Blueprint, jsonify, request

from app.services import ai_service

bp = ai_bp = Blueprint("ai", __name__)


@bp.route("/chat", methods=["POST"])
def chat():
    """Send a chat message and receive an AI response.

    JSON Body
    ---------
    session_id : str
        Unique conversation session identifier.
    message : str
        The user's message.
    """
    try:
        data: dict = request.get_json(force=True)
        session_id: str = data.get("session_id", "")
        message: str = data.get("message", "")

        if not session_id or not message:
            return jsonify({"error": "session_id and message are required"}), 400

        response_text = ai_service.process_chat(session_id=session_id, message=message)
        return jsonify({"session_id": session_id, "response": response_text}), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@bp.route("/history/<session_id>", methods=["GET"])
def get_history(session_id: str):
    """Return the full conversation history for a session.

    Parameters
    ----------
    session_id : str
        Session identifier (URL path parameter).
    """
    try:
        history = ai_service.get_conversation_history(session_id)
        return jsonify({"session_id": session_id, "messages": history}), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@bp.route("/history/<session_id>", methods=["DELETE"])
def clear_history(session_id: str):
    """Clear all messages for a conversation session.

    Parameters
    ----------
    session_id : str
        Session identifier (URL path parameter).
    """
    try:
        success = ai_service.clear_conversation(session_id)
        if success:
            return jsonify({"message": "Conversation cleared"}), 200
        return jsonify({"error": "Conversation not found"}), 404
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
