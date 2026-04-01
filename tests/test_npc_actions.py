"""Tests for NPCActionExecutor reactive/routine paths and RuleBasedNPCBehavior."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import pytest

from open_range.builder.npc.actions import (
    NPCActionExecutor,
    _extract_db_tables,
    _extract_shares,
    _extract_users,
    _extract_web_pages,
    _resolve_host,
    _username_from_persona,
)
from open_range.builder.npc.npc_agent import NPCAction, RuleBasedNPCBehavior, Stimulus
from open_range.world_ir import GreenPersona


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


def _make_persona(
    id_: str = "janet.liu",
    mailbox: str = "janet.liu@corp.local",
    awareness: float = 0.5,
    susceptibility: dict | None = None,
) -> GreenPersona:
    return GreenPersona(
        id=id_,
        role="Marketing Coordinator",
        department="Marketing",
        home_host="siem",
        mailbox=mailbox,
        awareness=awareness,
        susceptibility=susceptibility or {"phishing_email": 0.6},
        routine=("browse_app", "send_mail"),
    )


def _make_snapshot(
    hosts: list[Any] | None = None,
    users: list[Any] | None = None,
    files: dict[str, str] | None = None,
    domain: str = "corp.local",
) -> Any:
    topology = {
        "hosts": hosts or [
            {"name": "web", "services": ["nginx"]},
            {"name": "mail", "services": ["postfix"]},
            {"name": "db", "services": ["mysql"]},
            {"name": "siem", "services": ["rsyslog"]},
            {"name": "files", "services": ["samba"]},
        ],
        "users": users or [
            {"username": "alice", "hosts": ["web"]},
            {"username": "db_user", "hosts": ["db"], "password": "s3cr3t"},
        ],
        "domain": domain,
    }
    return SimpleNamespace(topology=topology, files=files or {})


def _make_executor(snapshot=None, containers=None) -> NPCActionExecutor:
    snap = snapshot or _make_snapshot()
    cont = containers or AsyncMock()
    cont.exec = AsyncMock(return_value="")
    return NPCActionExecutor(cont, snap)


def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# RuleBasedNPCBehavior
# ---------------------------------------------------------------------------


class TestRuleBasedBehavior:
    """Decision branches based on awareness x susceptibility x plausibility."""

    @pytest.fixture(autouse=True)
    def behavior(self):
        self.b = RuleBasedNPCBehavior()

    def _decide(self, persona, plausibility):
        return _run(
            self.b.decide(persona, Stimulus("phishing_email", "evil@bad.com", "Win prize", "", plausibility))
        )

    def test_high_awareness_low_score_reports(self):
        persona = _make_persona(awareness=0.9, susceptibility={"phishing_email": 0.5})
        # score = 0.5 * 0.5 = 0.25, awareness > 0.7, score < 0.8 -> report_to_IT
        result = self._decide(persona, plausibility=0.5)
        assert result.action == "report_to_IT"

    def test_high_score_clicks_link(self):
        persona = _make_persona(awareness=0.3, susceptibility={"phishing_email": 0.9})
        # score = 0.9 * 0.9 = 0.81 > 0.6 -> click_link
        result = self._decide(persona, plausibility=0.9)
        assert result.action == "click_link"

    def test_medium_score_ignores(self):
        persona = _make_persona(awareness=0.3, susceptibility={"phishing_email": 0.6})
        # score = 0.6 * 0.75 = 0.45 between 0.3 and 0.6 -> ignore
        result = self._decide(persona, plausibility=0.75)
        assert result.action == "ignore"

    def test_low_score_reports(self):
        persona = _make_persona(awareness=0.3, susceptibility={"phishing_email": 0.2})
        # score = 0.2 * 0.2 = 0.04 <= 0.3 -> report_to_IT
        result = self._decide(persona, plausibility=0.2)
        assert result.action == "report_to_IT"

    def test_missing_susceptibility_key_falls_back_to_phishing_email(self):
        persona = _make_persona(awareness=0.3, susceptibility={"phishing_email": 0.9})
        result = _run(
            self.b.decide(
                persona,
                Stimulus("unknown_type", "x@x.com", "test", "", plausibility=0.9),
            )
        )
        # falls back to phishing_email: score = 0.9 * 0.9 = 0.81 > 0.6 -> click_link
        assert result.action == "click_link"

    def test_high_awareness_score_at_threshold_reports(self):
        persona = _make_persona(awareness=0.8, susceptibility={"phishing_email": 0.7})
        # score = 0.7 * 1.0 = 0.7 < 0.8, awareness > 0.7 -> report_to_IT
        result = self._decide(persona, plausibility=1.0)
        assert result.action == "report_to_IT"


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


class TestHelpers:
    def test_resolve_host_dict_by_service(self):
        snap = _make_snapshot()
        assert _resolve_host(snap, ["nginx"], "fallback") == "web"

    def test_resolve_host_dict_by_name(self):
        snap = _make_snapshot()
        assert _resolve_host(snap, ["siem"], "fallback") == "siem"

    def test_resolve_host_string_list(self):
        snap = SimpleNamespace(topology={"hosts": ["nginx-srv", "mail-srv"]}, files={})
        assert _resolve_host(snap, ["nginx"], "fallback") == "nginx-srv"

    def test_resolve_host_no_match_returns_fallback(self):
        snap = _make_snapshot()
        assert _resolve_host(snap, ["nonexistent"], "myfallback") == "myfallback"

    def test_resolve_host_empty_topology_returns_fallback(self):
        snap = SimpleNamespace(topology={"hosts": []}, files={})
        assert _resolve_host(snap, ["web"], "fb") == "fb"

    def test_extract_web_pages(self):
        snap = _make_snapshot(files={
            "web:/var/www/html/index.php": "content",
            "web:/var/www/html/login.php": "",
            "db:sql": "CREATE TABLE t(id INT);",
        })
        pages = _extract_web_pages(snap)
        assert "/index.php" in pages
        assert "/login.php" in pages
        assert all(p.startswith("/") for p in pages)

    def test_extract_web_pages_fallback_to_root(self):
        snap = _make_snapshot(files={"db:sql": "SELECT 1"})
        assert _extract_web_pages(snap) == ["/"]

    def test_extract_shares(self):
        snap = _make_snapshot(files={
            "files:/srv/shares/finance/q1.xlsx": "",
            "files:/srv/shares/hr/policies.pdf": "",
        })
        shares = _extract_shares(snap)
        assert "finance" in shares
        assert "hr" in shares

    def test_extract_shares_fallback(self):
        snap = _make_snapshot(files={})
        assert _extract_shares(snap) == ["general"]

    def test_extract_db_tables(self):
        snap = _make_snapshot(files={
            "db:sql": (
                "INSERT INTO users (id, name) VALUES (1, 'a');\n"
                "SELECT * FROM orders;\n"
                "UPDATE products SET price=10;"
            )
        })
        tables = _extract_db_tables(snap)
        assert "users" in tables
        assert "orders" in tables
        assert "products" in tables

    def test_extract_users(self):
        snap = _make_snapshot(users=[
            {"username": "alice", "hosts": ["web"]},
            {"username": "bob", "hosts": ["mail"]},
            "not-a-dict",
        ])
        users = _extract_users(snap)
        assert "alice" in users
        assert "bob" in users
        assert "not-a-dict" not in users

    def test_username_from_persona_email(self):
        persona = _make_persona(mailbox="jane.doe@corp.local")
        assert _username_from_persona(persona) == "jane.doe"

    def test_username_from_persona_no_at_sign(self):
        persona = _make_persona(id_="bob.smith", mailbox="bobsmith")
        assert _username_from_persona(persona) == "bob.smith"


# ---------------------------------------------------------------------------
# NPCActionExecutor -- reactive executor (execute())
# ---------------------------------------------------------------------------


class TestReactiveExecutor:
    """executor.execute() routes NPCAction to the right handler."""

    def test_react_ignore_returns_blocked(self):
        executor = _make_executor()
        persona = _make_persona()
        result = _run(executor.execute(persona, NPCAction(action="ignore")))
        assert result["type"] == "social_engineering"
        assert result["result"] == "blocked"
        assert result["action"] == "ignore"

    def test_react_click_link_logs_success(self):
        executor = _make_executor()
        persona = _make_persona()
        result = _run(executor.execute(persona, NPCAction(action="click_link")))
        assert result["type"] == "social_engineering"
        assert result["action"] == "click_link"
        assert result["result"] == "success"

    def test_react_click_extracts_url_from_side_effects(self):
        executor = _make_executor()
        persona = _make_persona()
        _run(
            executor.execute(
                persona,
                NPCAction(action="click_link", side_effects=["clicked http://evil.example.com/payload"]),
            )
        )
        calls = [str(c) for c in executor.containers.exec.call_args_list]
        assert any("evil.example.com" in cmd for cmd in calls)

    def test_react_share_credentials_logs_success(self):
        executor = _make_executor()
        persona = _make_persona()
        result = _run(executor.execute(persona, NPCAction(action="share_credentials")))
        assert result["type"] == "social_engineering"
        assert result["action"] == "share_credentials"
        assert result["result"] == "success"

    def test_react_share_creds_calls_three_exec(self):
        """share_credentials: leak file + curl login + SIEM alert = 3 exec calls."""
        executor = _make_executor()
        persona = _make_persona()
        _run(executor.execute(persona, NPCAction(action="share_credentials")))
        assert executor.containers.exec.call_count == 3

    def test_react_report_to_it_logs_blocked(self):
        executor = _make_executor()
        persona = _make_persona()
        result = _run(
            executor.execute(
                persona,
                NPCAction(action="report_to_IT", side_effects=["suspicious email detected"]),
            )
        )
        assert result["type"] == "social_engineering"
        assert result["action"] == "report_to_IT"
        assert result["result"] == "blocked"

    def test_react_report_writes_to_siem_log(self):
        executor = _make_executor()
        persona = _make_persona()
        _run(executor.execute(persona, NPCAction(action="report_to_IT")))
        calls = [str(c) for c in executor.containers.exec.call_args_list]
        assert any("all.log" in c for c in calls)

    def test_react_reply_logs_success(self):
        executor = _make_executor()
        persona = _make_persona()
        result = _run(
            executor.execute(persona, NPCAction(action="reply", response_content="Acknowledged"))
        )
        assert result["type"] == "social_engineering"
        assert result["action"] == "reply"
        assert result["result"] == "success"

    def test_react_forward_same_as_reply(self):
        executor = _make_executor()
        persona = _make_persona()
        result = _run(executor.execute(persona, NPCAction(action="forward")))
        assert result["action"] == "forward"
        assert result["result"] == "success"

    def test_unknown_action_falls_back_to_ignore(self):
        executor = _make_executor()
        persona = _make_persona()
        result = _run(executor.execute(persona, NPCAction(action="nonexistent_action")))
        assert result["action"] == "ignore"
        assert result["result"] == "blocked"


# ---------------------------------------------------------------------------
# NPCActionExecutor -- routine executor (execute_routine())
# ---------------------------------------------------------------------------


class TestRoutineExecutor:
    """executor.execute_routine() produces the right log type per action."""

    def _executor_with(self, pages=None, shares=None, tables=None) -> NPCActionExecutor:
        files: dict[str, str] = {}
        if pages:
            for p in pages:
                files[f"web:/var/www/html{p}"] = ""
        if shares:
            for s in shares:
                files[f"files:/srv/shares/{s}/readme.txt"] = ""
        if tables:
            files["db:sql"] = " ".join(f"INSERT INTO {t} VALUES (1);" for t in tables)
        return _make_executor(snapshot=_make_snapshot(files=files))

    def test_browse_returns_web_request_log(self):
        executor = self._executor_with(pages=["/index.php"])
        persona = _make_persona()
        result = _run(executor.execute_routine(persona, "browse", "/index.php", "Browsing"))
        assert result["type"] == "web_request"
        assert result["label"] == "benign"
        assert "status_code" in result
        assert "bytes" in result
        assert "user_agent" in result

    def test_send_email_returns_npc_chat_log(self):
        executor = _make_executor()
        persona = _make_persona()
        result = _run(executor.execute_routine(persona, "send_email", "bob", "Quick update", "Hi Bob"))
        assert result["type"] == "npc_chat"
        assert result["recipient"] == "bob"

    def test_send_email_delivers_to_both_sent_and_inbox(self):
        executor = _make_executor()
        persona = _make_persona()
        _run(executor.execute_routine(persona, "send_email", "bob", "Update", "Body"))
        assert executor.containers.exec.call_count == 2
        calls = [str(c) for c in executor.containers.exec.call_args_list]
        assert any("inbox_" in c for c in calls)
        assert any("sent_" in c for c in calls)

    def test_lookup_returns_web_request_log(self):
        executor = self._executor_with(pages=["/search.php?q=test"])
        persona = _make_persona()
        result = _run(executor.execute_routine(persona, "lookup", "status", "Looking up"))
        assert result["type"] == "web_request"

    def test_access_share_returns_file_access_log(self):
        executor = self._executor_with(shares=["finance"])
        persona = _make_persona()
        result = _run(executor.execute_routine(persona, "access_share", "finance", ""))
        assert result["type"] == "file_access"
        assert result["share"] == "finance"

    def test_login_returns_auth_log(self):
        executor = self._executor_with(pages=["/login.php"])
        persona = _make_persona()
        result = _run(executor.execute_routine(persona, "login", "/login.php", "Portal login"))
        assert result["type"] == "auth"
        assert result["outcome"] == "success"

    def test_query_db_returns_db_query_log(self):
        executor = self._executor_with(tables=["orders"])
        persona = _make_persona()
        result = _run(executor.execute_routine(persona, "query_db", "orders", ""))
        assert result["type"] == "db_query"
        assert "query" in result

    def test_idle_returns_system_activity_log(self):
        executor = _make_executor()
        persona = _make_persona()
        result = _run(executor.execute_routine(persona, "idle", "", "Lunch break"))
        assert result["type"] == "system_activity"

    def test_unknown_action_falls_back_to_idle(self):
        executor = _make_executor()
        persona = _make_persona()
        result = _run(executor.execute_routine(persona, "unknown_action", "", ""))
        assert result["type"] == "system_activity"

    def test_persona_id_present_in_all_log_types(self):
        executor = _make_executor()
        persona = _make_persona(id_="janet.liu")
        for action in ("browse", "send_email", "lookup", "access_share", "login", "query_db", "idle"):
            result = _run(executor.execute_routine(persona, action, "", ""))
            assert result["persona"] == "janet.liu", f"Missing persona for action={action}"
