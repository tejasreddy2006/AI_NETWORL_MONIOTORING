"""NetGuard AI — AI Conversation model.

Stores chat messages exchanged between users and the AI copilot,
grouped by session ID.
"""

from __future__ import annotations

import enum
from datetime import datetime
from typing import Any, Dict, Optional

from app.extensions import db


class MessageRole(enum.Enum):
    """Chat message author roles."""

    user = "user"
    assistant = "assistant"
    system = "system"


class AIConversation(db.Model):  # type: ignore[name-defined]
    """A single message in an AI copilot conversation."""

    __tablename__ = "ai_conversations"

    id: int = db.Column(db.Integer, primary_key=True, autoincrement=True)
    session_id: str = db.Column(db.String(36), nullable=False, index=True)
    role: str = db.Column(db.Enum(MessageRole), nullable=False)
    content: str = db.Column(db.Text, nullable=False)
    context_used: Optional[Dict[str, Any]] = db.Column(db.JSON, nullable=True)
    created_at: datetime = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    # ── Serialisation ─────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable dictionary."""
        return {
            "id": self.id,
            "session_id": self.session_id,
            "role": self.role.value if isinstance(self.role, MessageRole) else self.role,
            "content": self.content,
            "context_used": self.context_used,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:
        return f"<AIConversation {self.id} [{self.role}] session={self.session_id[:8]}…>"
