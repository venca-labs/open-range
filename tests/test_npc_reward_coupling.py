"""Tests for NPC ↔ reward system coupling.

Validates that NPC log entries contain the fields the reward system expects:
- ``label: "benign"`` on routine NPC actions (for FP penalty)
- ``source`` on all NPC log entries (for FP detection)
- ``type: "social_engineering"`` on reactive actions (for Red/Blue SE rewards)
- ``result: "success"/"blocked"`` on reactive actions

Also tests credential extraction from snapshot topology.
"""

from __future__ import annotations

import pytest

from open_range.builder.npc.actions import (
    NPCActionExecutor,
    _extract_db_credentials,
    _extract_db_tables,
    _extract_shares,
    _extract_ssh_credentials,
    _extract_users,
    _extract_web_pages,
    _log,
    _se_log,
)
from open_range.builder.npc.channels import ChatChannel, DocumentChannel, VoiceChannel
from open_range.builder.npc.chat_traffic import generate_chat_traffic
from open_range.protocols import NPCPersona, SnapshotSpec


# ===================================================================
# Fixtures
# ===================================================================


@pytest.fixture
def persona_low() -> NPCPersona:
    return NPCPersona(
        name="Alice Doe",
        role="Receptionist",
        department="Admin",
        security_awareness=0.2,
        susceptibility={"phishing_email": 0.8, "vishing": 0.7},
        accounts={"email": "adoe@corp.local"},
    )


@pytest.fixture
def persona_high() -> NPCPersona:
    return NPCPersona(
        name="Bob Smith",
        role="CISO",
        department="Security",
        security_awareness=0.95,
        susceptibility={"phishing_email": 0.1, "vishing": 0.1},
        accounts={"email": "bsmith@corp.local"},
    )


@pytest.fixture
def snapshot_with_creds() -> SnapshotSpec:
    return SnapshotSpec(
        topology={
            "domain": "example.local",
            "users": [
                {"username": "dbadmin", "password": "S3cur3DB!", "hosts": ["db"]},
                {"username": "sysop", "password": "R00tPw!", "hosts": ["web", "files"], "role": "admin"},
                {"username": "appuser", "password": "AppPw123", "hosts": ["web"]},
            ],
        },
        files={
            "web:/var/www/html/index.php": "<?php echo 'hi'; ?>",
            "web:/var/www/html/login.php": "<?php // login ?>",
            "files:/srv/shares/finance/report.xlsx": "data",
            "files:/srv/shares/hr/employees.csv": "data",
            "db:sql": "CREATE TABLE app_db.users (id INT); INSERT INTO app_db.orders VALUES (1);",
        },
    )


@pytest.fixture
def snapshot_no_creds() -> SnapshotSpec:
    return SnapshotSpec(topology={}, files={})


# ===================================================================
# Routine action log labels
# ===================================================================


class TestRoutineLogLabels:
    """Routine NPC actions must have label='benign' and a source field."""

    def test_log_has_benign_label(self, persona_low):
        entry = _log(persona_low, "browse", "Browsed /index.php", "web:/index.php")
        assert entry["label"] == "benign"

    def test_log_has_source(self, persona_low):
        entry = _log(persona_low, "browse", "Browsed /index.php", "web:/index.php")
        assert entry["source"] == "web:/index.php"

    def test_log_has_type_prefix(self, persona_low):
        entry = _log(persona_low, "query_db", "Queried users", "db:query_log")
        assert entry["type"] == "npc_query_db"

    def test_log_has_persona(self, persona_low):
        entry = _log(persona_low, "idle", "Reading", "none")
        assert entry["persona"] == "Alice Doe"
        assert entry["department"] == "Admin"


# ===================================================================
# Reactive (social engineering) log labels
# ===================================================================


class TestSELogLabels:
    """Reactive NPC actions must have type='social_engineering' and result."""

    def test_se_log_type(self, persona_low):
        entry = _se_log(persona_low, "click_link", "Clicked link", "web:access_log", result="success")
        assert entry["type"] == "social_engineering"

    def test_se_log_result_success(self, persona_low):
        entry = _se_log(persona_low, "click_link", "Clicked", "web:access_log", result="success")
        assert entry["result"] == "success"

    def test_se_log_result_blocked(self, persona_high):
        entry = _se_log(persona_high, "report_to_IT", "Reported", "siem:alert", result="blocked")
        assert entry["result"] == "blocked"

    def test_se_log_label_reactive(self, persona_low):
        entry = _se_log(persona_low, "share_credentials", "Leaked", "web+siem", result="success")
        assert entry["label"] == "reactive"

    def test_se_log_has_persona(self, persona_low):
        entry = _se_log(persona_low, "ignore", "Ignored", "none", result="blocked")
        assert entry["persona"] == "Alice Doe"


# ===================================================================
# Channel log labels
# ===================================================================


class TestChannelLogLabels:
    """Channel log entries must have label='benign' and source."""

    def test_chat_channel_log_has_label(self):
        ch = ChatChannel()
        ch.send_message("Alice", "Bob", "Hello!")
        logs = ch.get_channel_log()
        assert len(logs) == 1
        assert logs[0]["label"] == "benign"
        assert "source" in logs[0]

    def test_voice_channel_log_has_label(self, persona_low):
        ch = VoiceChannel()
        call = ch.initiate_call("Attacker", "Alice", "IT support here")
        ch.respond(persona_low, call)
        logs = ch.get_call_log()
        assert len(logs) == 1
        assert logs[0]["label"] == "benign"
        assert logs[0]["source"] == "voice:phone"

    def test_document_channel_log_has_label(self, persona_low):
        ch = DocumentChannel()
        doc = ch.share_document("Attacker", "Alice", "report.pdf", "Quarterly report")
        ch.inspect_document(persona_low, doc)
        logs = ch.get_document_log()
        assert len(logs) == 1
        assert logs[0]["label"] == "benign"
        assert "source" in logs[0]


class TestChatTrafficLabels:
    """Chat traffic generation should produce labeled log entries."""

    def test_generated_chat_has_labels(self, persona_low, persona_high):
        ch = ChatChannel()
        generate_chat_traffic(
            personas=[persona_low, persona_high],
            channel=ch,
            num_messages=5,
            seed=42,
        )
        logs = ch.get_channel_log()
        assert len(logs) == 5
        for entry in logs:
            assert entry["label"] == "benign"
            assert "source" in entry


# ===================================================================
# Credential extraction from snapshot topology
# ===================================================================


class TestCredentialExtraction:
    """Credentials should be pulled from snapshot topology, not hardcoded."""

    def test_db_creds_from_topology(self, snapshot_with_creds):
        user, pwd = _extract_db_credentials(snapshot_with_creds)
        assert user == "dbadmin"
        assert pwd == "S3cur3DB!"

    def test_db_creds_fallback(self, snapshot_no_creds):
        user, pwd = _extract_db_credentials(snapshot_no_creds)
        assert user == "app_user"
        assert pwd == "AppUs3r!2024"

    def test_ssh_creds_from_topology(self, snapshot_with_creds):
        user, pwd = _extract_ssh_credentials(snapshot_with_creds)
        assert user == "sysop"
        assert pwd == "R00tPw!"

    def test_ssh_creds_fallback(self, snapshot_no_creds):
        user, pwd = _extract_ssh_credentials(snapshot_no_creds)
        assert user == "admin"
        assert pwd == "Adm1n!2024"


# ===================================================================
# Snapshot introspection
# ===================================================================


class TestSnapshotIntrospection:
    """Verify snapshot-derived targets are generalizable."""

    def test_extract_web_pages(self, snapshot_with_creds):
        pages = _extract_web_pages(snapshot_with_creds)
        assert "/index.php" in pages
        assert "/login.php" in pages

    def test_extract_shares(self, snapshot_with_creds):
        shares = _extract_shares(snapshot_with_creds)
        assert "finance" in shares
        assert "hr" in shares

    def test_extract_db_tables(self, snapshot_with_creds):
        tables = _extract_db_tables(snapshot_with_creds)
        assert "app_db.orders" in tables or "app_db.users" in tables

    def test_extract_users(self, snapshot_with_creds):
        users = _extract_users(snapshot_with_creds)
        assert "dbadmin" in users
        assert "sysop" in users

    def test_empty_snapshot_pages(self, snapshot_no_creds):
        pages = _extract_web_pages(snapshot_no_creds)
        assert pages == ["/"]

    def test_empty_snapshot_shares(self, snapshot_no_creds):
        shares = _extract_shares(snapshot_no_creds)
        assert shares == ["general"]


# ===================================================================
# Reward coupling integration
# ===================================================================


class TestRewardCoupling:
    """End-to-end: NPC logs feed into reward computation correctly."""

    def test_red_social_reward_recognizes_se_logs(self):
        """CompositeRedReward.compute() should find social_engineering entries."""
        from open_range.server.rewards import CompositeRedReward
        from open_range.server.models import RangeAction, RangeObservation, RangeState

        reward = CompositeRedReward()
        action = RangeAction(command="nmap -sV web", mode="red")
        obs = RangeObservation(stdout="")
        state = RangeState(step_count=1, tier=1)
        snapshot = SnapshotSpec()

        # NPC log with a successful social engineering event
        ctx = {
            "red_history": [],
            "blue_history": [],
            "npc_traffic_log": [
                {
                    "type": "social_engineering",
                    "label": "reactive",
                    "persona": "Alice",
                    "action": "click_link",
                    "result": "success",
                    "source": "web:access_log",
                    "timestamp": 1.0,
                },
            ],
        }

        score = reward.compute(action, obs, state, snapshot, ctx)
        # social weight is 0.05, score is 1.0, tier 1 multiplier is 1.0
        # So social contribution = 0.05 * 1.0 = 0.05
        # Total should include social component
        assert score > 0  # At minimum efficiency + social contribute

    def test_blue_fp_penalty_uses_benign_label(self):
        """CompositeBlueReward should penalize findings that match benign NPC sources."""
        from open_range.server.rewards import CompositeBlueReward
        from open_range.server.models import RangeAction, RangeObservation, RangeState

        reward = CompositeBlueReward()
        action = RangeAction(command="grep suspicious /var/log/siem/all.log", mode="blue")
        obs = RangeObservation(stdout="")
        state = RangeState(step_count=1, tier=1)
        snapshot = SnapshotSpec()

        # Blue submits a finding that matches a benign NPC source
        ctx = {
            "red_history": [],
            "blue_history": [
                {"type": "finding", "content": "Suspicious activity from chat:general"},
            ],
            "npc_traffic_log": [
                {
                    "type": "chat",
                    "label": "benign",
                    "source": "chat:general",
                    "persona": "Alice",
                    "timestamp": 1.0,
                },
            ],
        }

        score = reward.compute(action, obs, state, snapshot, ctx)
        # Should have FP penalty (-0.2 per false positive)
        assert score < 0

    def test_blue_phishing_detection_reward(self):
        """Blue gets phishing reward when SE events exist and Blue detects them."""
        from open_range.server.rewards import CompositeBlueReward
        from open_range.server.models import RangeAction, RangeObservation, RangeState

        reward = CompositeBlueReward()
        action = RangeAction(command="grep phish /var/log/siem/all.log", mode="blue")
        obs = RangeObservation(stdout="")
        state = RangeState(step_count=1, tier=1)
        snapshot = SnapshotSpec()

        ctx = {
            "red_history": [],
            "blue_history": [
                {"type": "finding", "content": "Detected phishing email to Alice"},
            ],
            "npc_traffic_log": [
                {
                    "type": "social_engineering",
                    "label": "reactive",
                    "persona": "Alice",
                    "action": "click_link",
                    "result": "success",
                    "source": "web:access_log",
                    "timestamp": 1.0,
                },
            ],
        }

        score = reward.compute(action, obs, state, snapshot, ctx)
        # phishing weight is 0.05, Blue detected 1/1 SE events
        assert score > 0
