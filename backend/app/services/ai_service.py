"""
NetGuard AI — AI Chat Service.

Provides business logic for processing conversational AI queries,
managing conversation history, and session lifecycle.
"""

from __future__ import annotations

from typing import Any

from flask import current_app

from app.extensions import db
from app.models.conversation import AIConversation, MessageRole


def process_chat(session_id: str, message: str) -> str:
    """Process an incoming chat message and return the AI response.

    Parameters
    ----------
    session_id : str
        Unique identifier for the conversation session.
    message : str
        The user's chat message.

    Returns
    -------
    str
        The AI-generated response text.
    """
    # Log user message
    user_msg = AIConversation(
        session_id=session_id,
        role=MessageRole.user,
        content=message,
    )
    db.session.add(user_msg)
    db.session.commit()

    # Get the registered AI Copilot engine, or create one with app context
    engine = current_app.extensions.get("ai_copilot")
    if not engine:
        from app.engines.ai_copilot import AICopilotEngine
        engine = AICopilotEngine(current_app._get_current_object())

    response = engine.chat(session_id, message)

    # Log AI assistant response
    assistant_msg = AIConversation(
        session_id=session_id,
        role=MessageRole.assistant,
        content=response,
    )
    db.session.add(assistant_msg)
    db.session.commit()

    return response


def get_conversation_history(session_id: str) -> list[dict[str, Any]]:
    """Retrieve the full conversation history for a session.

    Parameters
    ----------
    session_id : str
        Session identifier.

    Returns
    -------
    list[dict]
        Chronologically ordered messages:
        ``[{"role": str, "content": str, "timestamp": str}, ...]``
    """
    msgs = (
        AIConversation.query.filter(AIConversation.session_id == session_id)
        .order_by(AIConversation.created_at.asc())
        .all()
    )
    return [m.to_dict() for m in msgs]


def clear_conversation(session_id: str) -> bool:
    """Delete all messages associated with a conversation session.

    Parameters
    ----------
    session_id : str
        Session identifier.

    Returns
    -------
    bool
        ``True`` if the conversation was successfully cleared.
    """
    AIConversation.query.filter(AIConversation.session_id == session_id).delete()
    db.session.commit()
    return True
