"""Tests for multimodal NPC communication channels (issue #30).

Tests ChatChannel, VoiceChannel, DocumentChannel, chat traffic
generation, and SIEM log aggregation. No Docker dependency.
"""

from __future__ import annotations

import pytest

from open_range.builder.npc.channels import (
    ChatChannel,
    ChatMessage,
    DocumentChannel,
    DocumentRecord,
    NPCChannel,
    VoiceChannel,
    VoiceTranscript,
)
from open_range.builder.npc.chat_traffic import generate_chat_traffic
from open_range.builder.npc.npc_manager import NPCManager
from open_range.protocols import NPCPersona, NPCTrafficSpec, SnapshotSpec, TaskSpec


# ===================================================================
# Fixtures
# ===================================================================


@pytest.fixture
def low_awareness_persona() -> NPCPersona:
    return NPCPersona(
        name="Janet Smith",
        role="Marketing Coordinator",
        department="Marketing",
        security_awareness=0.2,
        susceptibility={
            "phishing_email": 0.8,
            "attachment_opening": 0.9,
            "vishing": 0.7,
            "credential_sharing": 0.6,
        },
    )


@pytest.fixture
def high_awareness_persona() -> NPCPersona:
    return NPCPersona(
        name="David Chen",
        role="CISO",
        department="Security",
        security_awareness=0.95,
        susceptibility={
            "phishing_email": 0.05,
            "attachment_opening": 0.1,
            "vishing": 0.05,
            "credential_sharing": 0.01,
        },
    )


@pytest.fixture
def two_personas(
    low_awareness_persona: NPCPersona,
    high_awareness_persona: NPCPersona,
) -> list[NPCPersona]:
    return [low_awareness_persona, high_awareness_persona]


# ===================================================================
# NPCChannel enum
# ===================================================================


class TestNPCChannel:
    def test_enum_values(self):
        assert NPCChannel.EMAIL == "email"
        assert NPCChannel.CHAT == "chat"
        assert NPCChannel.VOICE == "voice"
        assert NPCChannel.DOCUMENT == "document"


# ===================================================================
# ChatChannel
# ===================================================================


class TestChatChannel:
    def test_send_and_receive(self):
        ch = ChatChannel()
        ch.send_message("Alice", "Bob", "Hello Bob!")
        msgs = ch.get_messages("Bob")
        assert len(msgs) == 1
        assert msgs[0].sender == "Alice"
        assert msgs[0].content == "Hello Bob!"

    def test_get_messages_filters_by_recipient(self):
        ch = ChatChannel()
        ch.send_message("Alice", "Bob", "For Bob")
        ch.send_message("Alice", "Carol", "For Carol")
        assert len(ch.get_messages("Bob")) == 1
        assert len(ch.get_messages("Carol")) == 1
        assert len(ch.get_messages("Dave")) == 0

    def test_channel_log_returns_all(self):
        ch = ChatChannel()
        ch.send_message("Alice", "Bob", "msg1")
        ch.send_message("Carol", "Dave", "msg2")
        log = ch.get_channel_log()
        assert len(log) == 2
        assert all(entry["type"] == "chat" for entry in log)
        assert log[0]["sender"] == "Alice"
        assert log[1]["sender"] == "Carol"

    def test_clear(self):
        ch = ChatChannel()
        ch.send_message("A", "B", "test")
        ch.clear()
        assert ch.get_channel_log() == []
        assert ch.get_messages("B") == []

    def test_message_has_timestamp(self):
        ch = ChatChannel()
        msg = ch.send_message("A", "B", "ts test")
        assert isinstance(msg.timestamp, float)
        assert msg.timestamp > 0

    def test_send_returns_chat_message(self):
        ch = ChatChannel()
        msg = ch.send_message("A", "B", "hello")
        assert isinstance(msg, ChatMessage)


# ===================================================================
# VoiceChannel
# ===================================================================


class TestVoiceChannel:
    def test_initiate_call(self):
        ch = VoiceChannel()
        call = ch.initiate_call(
            caller="Attacker",
            callee="Janet Smith",
            pretext="Hi, this is IT support. I need your password for a security check.",
        )
        assert isinstance(call, VoiceTranscript)
        assert call.caller == "Attacker"
        assert call.callee == "Janet Smith"
        assert len(call.transcript) == 1
        assert call.transcript[0]["speaker"] == "Attacker"

    def test_respond_low_awareness(self, low_awareness_persona: NPCPersona):
        ch = VoiceChannel()
        call = ch.initiate_call("Attacker", low_awareness_persona.name, "Need your creds")
        result = ch.respond(low_awareness_persona, call)
        assert len(result.transcript) == 2
        assert result.response_action in ("comply", "deflect", "refuse")
        # Low awareness + high vishing susceptibility -> comply
        assert result.response_action == "comply"

    def test_respond_high_awareness(self, high_awareness_persona: NPCPersona):
        ch = VoiceChannel()
        call = ch.initiate_call("Attacker", high_awareness_persona.name, "Need your password")
        result = ch.respond(high_awareness_persona, call)
        assert result.response_action == "report_to_IT"
        assert len(result.transcript) == 2

    def test_get_call_log(self):
        ch = VoiceChannel()
        ch.initiate_call("A", "B", "pretext1")
        ch.initiate_call("C", "D", "pretext2")
        log = ch.get_call_log()
        assert len(log) == 2
        assert all(entry["type"] == "voice" for entry in log)

    def test_clear(self):
        ch = VoiceChannel()
        ch.initiate_call("A", "B", "test")
        ch.clear()
        assert ch.get_call_log() == []

    def test_call_has_timestamp(self):
        ch = VoiceChannel()
        call = ch.initiate_call("A", "B", "test")
        assert isinstance(call.timestamp, float)
        assert call.timestamp > 0

    def test_respond_sets_duration(self, low_awareness_persona: NPCPersona):
        ch = VoiceChannel()
        call = ch.initiate_call("A", low_awareness_persona.name, "hello")
        result = ch.respond(low_awareness_persona, call)
        assert result.duration_s > 0


# ===================================================================
# DocumentChannel
# ===================================================================


class TestDocumentChannel:
    def test_share_document(self):
        ch = DocumentChannel()
        doc = ch.share_document("Alice", "Bob", "report.pdf", "Q4 financial report")
        assert isinstance(doc, DocumentRecord)
        assert doc.sender == "Alice"
        assert doc.recipient == "Bob"
        assert doc.filename == "report.pdf"
        assert doc.accessed is False

    def test_inspect_low_awareness(self, low_awareness_persona: NPCPersona):
        ch = DocumentChannel()
        doc = ch.share_document("Attacker", low_awareness_persona.name, "malware.docx", "Invoice")
        decision = ch.inspect_document(low_awareness_persona, doc)
        # Low awareness + high attachment_opening susceptibility -> opened
        assert decision == "opened"
        assert doc.accessed is True
        assert doc.access_decision == "opened"

    def test_inspect_high_awareness(self, high_awareness_persona: NPCPersona):
        ch = DocumentChannel()
        doc = ch.share_document("Attacker", high_awareness_persona.name, "malware.docx", "Invoice")
        decision = ch.inspect_document(high_awareness_persona, doc)
        assert decision == "reported"
        assert doc.accessed is False
        assert doc.access_decision == "reported"

    def test_get_document_log(self):
        ch = DocumentChannel()
        ch.share_document("A", "B", "f1.txt", "desc1")
        ch.share_document("C", "D", "f2.txt", "desc2")
        log = ch.get_document_log()
        assert len(log) == 2
        assert all(entry["type"] == "document" for entry in log)

    def test_clear(self):
        ch = DocumentChannel()
        ch.share_document("A", "B", "f.txt", "d")
        ch.clear()
        assert ch.get_document_log() == []

    def test_document_has_timestamp(self):
        ch = DocumentChannel()
        doc = ch.share_document("A", "B", "f.txt", "d")
        assert isinstance(doc.timestamp, float)
        assert doc.timestamp > 0


# ===================================================================
# Chat traffic generator
# ===================================================================


class TestChatTraffic:
    def test_generate_messages(self, two_personas: list[NPCPersona]):
        ch = ChatChannel()
        msgs = generate_chat_traffic(two_personas, ch, num_messages=5, seed=42)
        assert len(msgs) == 5
        assert all("sender" in m for m in msgs)
        assert all("recipient" in m for m in msgs)
        assert all("content" in m for m in msgs)

    def test_deterministic_with_seed(self, two_personas: list[NPCPersona]):
        ch1 = ChatChannel()
        msgs1 = generate_chat_traffic(two_personas, ch1, num_messages=5, seed=99)
        ch2 = ChatChannel()
        msgs2 = generate_chat_traffic(two_personas, ch2, num_messages=5, seed=99)
        # Same seed -> same messages
        assert [m["content"] for m in msgs1] == [m["content"] for m in msgs2]

    def test_no_self_messages(self, two_personas: list[NPCPersona]):
        ch = ChatChannel()
        msgs = generate_chat_traffic(two_personas, ch, num_messages=20, seed=1)
        for m in msgs:
            assert m["sender"] != m["recipient"]

    def test_empty_with_fewer_than_two_personas(self):
        ch = ChatChannel()
        single = [NPCPersona(name="Solo")]
        msgs = generate_chat_traffic(single, ch, num_messages=5)
        assert msgs == []

    def test_messages_appear_in_channel(self, two_personas: list[NPCPersona]):
        ch = ChatChannel()
        generate_chat_traffic(two_personas, ch, num_messages=5, seed=42)
        log = ch.get_channel_log()
        assert len(log) == 5


# ===================================================================
# SIEM log aggregation (NPCManager)
# ===================================================================


class TestChannelSIEM:
    def test_siem_log_aggregates_channels(self):
        mgr = NPCManager()
        chat_ch = mgr.channels["chat"]
        voice_ch = mgr.channels["voice"]
        doc_ch = mgr.channels["document"]

        assert isinstance(chat_ch, ChatChannel)
        assert isinstance(voice_ch, VoiceChannel)
        assert isinstance(doc_ch, DocumentChannel)

        chat_ch.send_message("A", "B", "hello")
        voice_ch.initiate_call("C", "D", "pretext")
        doc_ch.share_document("E", "F", "file.txt", "desc")

        log = mgr.get_siem_log()
        assert len(log) == 3
        types = {entry["type"] for entry in log}
        assert types == {"chat", "voice", "document"}

    def test_siem_log_sorted_by_timestamp(self):
        mgr = NPCManager()
        chat_ch = mgr.channels["chat"]
        assert isinstance(chat_ch, ChatChannel)

        # Send multiple messages
        chat_ch.send_message("A", "B", "first")
        chat_ch.send_message("C", "D", "second")

        log = mgr.get_siem_log()
        timestamps = [e["timestamp"] for e in log]
        assert timestamps == sorted(timestamps)

    def test_channels_reinitialised_on_start(self):
        """Verify that channels dict exists on a fresh NPCManager."""
        mgr = NPCManager()
        assert "chat" in mgr.channels
        assert "voice" in mgr.channels
        assert "document" in mgr.channels
