"""Multimodal NPC communication channels.

Provides ChatChannel, VoiceChannel, and DocumentChannel for NPC
interactions beyond simple email. All channel activity is logged
for SIEM consumption by the Blue team.
"""

from __future__ import annotations

import time
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from open_range.protocols import NPCPersona


class NPCChannel(str, Enum):
    """Supported NPC communication channel types."""

    EMAIL = "email"
    CHAT = "chat"
    VOICE = "voice"
    DOCUMENT = "document"


# ---------------------------------------------------------------------------
# Chat Channel
# ---------------------------------------------------------------------------


class ChatMessage(BaseModel):
    """A single chat message in the internal messaging system."""

    sender: str
    recipient: str
    content: str
    timestamp: float = Field(default_factory=time.time)
    channel: str = "general"


class ChatChannel:
    """Internal messaging/chat system for NPC communication.

    NPCs can send and receive messages. All traffic is logged for
    Blue team SIEM consumption.
    """

    def __init__(self) -> None:
        self._messages: list[ChatMessage] = []

    def send_message(
        self,
        sender: str,
        recipient: str,
        content: str,
        channel: str = "general",
    ) -> ChatMessage:
        """Queue a chat message from sender to recipient."""
        msg = ChatMessage(
            sender=sender,
            recipient=recipient,
            content=content,
            channel=channel,
        )
        self._messages.append(msg)
        return msg

    def get_messages(self, user: str) -> list[ChatMessage]:
        """Get all messages for a given user (as recipient)."""
        return [m for m in self._messages if m.recipient == user]

    def get_channel_log(self) -> list[dict[str, Any]]:
        """Return all messages as dicts for Blue team SIEM integration."""
        return [
            {
                "type": "chat",
                "sender": m.sender,
                "recipient": m.recipient,
                "content": m.content,
                "timestamp": m.timestamp,
                "channel": m.channel,
            }
            for m in self._messages
        ]

    def clear(self) -> None:
        """Clear all messages."""
        self._messages.clear()


# ---------------------------------------------------------------------------
# Voice Channel
# ---------------------------------------------------------------------------


class VoiceTranscript(BaseModel):
    """Transcript of a voice/phone call between two parties."""

    caller: str
    callee: str
    pretext: str
    response_action: str = "ignore"
    transcript: list[dict[str, str]] = Field(default_factory=list)
    timestamp: float = Field(default_factory=time.time)
    duration_s: float = 0.0


class VoiceChannel:
    """Phone/voice call simulation (text-based transcript).

    Supports social engineering scenarios where Red might attempt
    vishing attacks against NPC employees.
    """

    def __init__(self) -> None:
        self._calls: list[VoiceTranscript] = []

    def initiate_call(
        self,
        caller: str,
        callee: str,
        pretext: str,
    ) -> VoiceTranscript:
        """Start a voice interaction with a pretext.

        Returns a VoiceTranscript with the initial caller entry.
        """
        transcript = VoiceTranscript(
            caller=caller,
            callee=callee,
            pretext=pretext,
            transcript=[{"speaker": caller, "text": pretext}],
        )
        self._calls.append(transcript)
        return transcript

    def respond(
        self,
        callee_persona: NPCPersona,
        call: VoiceTranscript,
    ) -> VoiceTranscript:
        """NPC decides how to respond to a voice call based on persona.

        Uses rule-based heuristics (susceptibility scores) to decide.
        Returns the updated transcript.
        """
        susceptibility = callee_persona.susceptibility.get("vishing", 0.5)

        if callee_persona.security_awareness > 0.7:
            response_text = (
                "I need to verify your identity before providing any information. "
                "Let me transfer you to the security team."
            )
            action = "report_to_IT"
        elif susceptibility > 0.6:
            response_text = (
                "Sure, I can help with that. What information do you need?"
            )
            action = "comply"
        elif susceptibility > 0.3:
            response_text = (
                "I'm not sure about that. Can you send me an email instead?"
            )
            action = "deflect"
        else:
            response_text = (
                "I don't feel comfortable sharing that over the phone. "
                "Please contact my manager."
            )
            action = "refuse"

        call.transcript.append(
            {"speaker": callee_persona.name, "text": response_text}
        )
        call.response_action = action
        call.duration_s = 30.0  # simulated call duration
        return call

    def get_call_log(self) -> list[dict[str, Any]]:
        """Return all calls as dicts for Blue team SIEM integration."""
        return [
            {
                "type": "voice",
                "caller": c.caller,
                "callee": c.callee,
                "pretext": c.pretext,
                "response_action": c.response_action,
                "transcript": c.transcript,
                "timestamp": c.timestamp,
                "duration_s": c.duration_s,
            }
            for c in self._calls
        ]

    def clear(self) -> None:
        """Clear all call records."""
        self._calls.clear()


# ---------------------------------------------------------------------------
# Document Channel
# ---------------------------------------------------------------------------


class DocumentRecord(BaseModel):
    """Record of a shared document and its access history."""

    sender: str
    recipient: str
    filename: str
    content_description: str
    timestamp: float = Field(default_factory=time.time)
    accessed: bool = False
    access_decision: str = ""  # "opened", "ignored", "reported"


class DocumentChannel:
    """Document sharing/inspection system for NPC interactions.

    Tracks document sharing and access decisions for Blue team
    monitoring (e.g., detecting malicious document opens).
    """

    def __init__(self) -> None:
        self._documents: list[DocumentRecord] = []

    def share_document(
        self,
        sender: str,
        recipient: str,
        filename: str,
        content_description: str,
    ) -> DocumentRecord:
        """Share a document with a recipient."""
        doc = DocumentRecord(
            sender=sender,
            recipient=recipient,
            filename=filename,
            content_description=content_description,
        )
        self._documents.append(doc)
        return doc

    def inspect_document(
        self,
        persona: NPCPersona,
        document: DocumentRecord,
    ) -> str:
        """NPC decides how to handle a received document.

        Returns the decision: "opened", "ignored", or "reported".
        Uses rule-based heuristics based on persona susceptibility.
        """
        susceptibility = persona.susceptibility.get("attachment_opening", 0.5)

        if persona.security_awareness > 0.7:
            decision = "reported"
        elif susceptibility > 0.6:
            decision = "opened"
        else:
            decision = "ignored"

        document.accessed = decision == "opened"
        document.access_decision = decision
        return decision

    def get_document_log(self) -> list[dict[str, Any]]:
        """Return all document records for Blue team SIEM integration."""
        return [
            {
                "type": "document",
                "sender": d.sender,
                "recipient": d.recipient,
                "filename": d.filename,
                "content_description": d.content_description,
                "timestamp": d.timestamp,
                "accessed": d.accessed,
                "access_decision": d.access_decision,
            }
            for d in self._documents
        ]

    def clear(self) -> None:
        """Clear all document records."""
        self._documents.clear()
