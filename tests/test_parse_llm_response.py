"""Tests for _parse_llm_response() — the critical LLM JSON -> SnapshotSpec mapper.

Covers field name aliases, evidence spec formats, NPC persona parsing,
files dict extraction, missing/minimal/malformed input, and a real LLM
output fixture from snapshots/llm_tier1_test.json.
"""

import json
from pathlib import Path

import pytest

from open_range.builder.builder import SnapshotParseError, _parse_llm_response
from open_range.protocols import (
    EvidenceItem,
    ExploitStep,
    FlagSpec,
    GoldenPathStep,
    NPCPersona,
    SnapshotSpec,
    Vulnerability,
)

ROOT = Path(__file__).parent.parent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _minimal_json(**overrides) -> str:
    """Return a minimal valid JSON string for _parse_llm_response.

    All top-level keys present but with empty/default values unless overridden.
    """
    base: dict = {
        "topology": {},
        "truth_graph": {"vulns": [], "exploit_chain": []},
        "golden_path": [],
        "flags": [],
        "evidence_spec": {},
        "npc_personas": [],
        "npc_traffic": {},
        "task": {},
    }
    base.update(overrides)
    return json.dumps(base)


# ---------------------------------------------------------------------------
# 1. Happy path with real LLM output
# ---------------------------------------------------------------------------


class TestRealLLMOutput:
    """Parse the actual LLM-generated JSON from snapshots/llm_tier1_test.json."""

    @pytest.fixture
    def llm_json(self):
        path = ROOT / "snapshots" / "llm_tier1_test.json"
        return path.read_text()

    def test_parses_to_snapshot_spec(self, llm_json):
        spec = _parse_llm_response(llm_json)
        assert isinstance(spec, SnapshotSpec)

    def test_topology_hosts(self, llm_json):
        spec = _parse_llm_response(llm_json)
        hosts = spec.topology["hosts"]
        assert "attacker" in hosts
        assert "web" in hosts
        assert "siem" in hosts
        assert len(hosts) == 8

    def test_topology_zones(self, llm_json):
        spec = _parse_llm_response(llm_json)
        zones = spec.topology["zones"]
        assert "dmz" in zones
        assert "web" in zones["dmz"]

    def test_truth_graph_vulns(self, llm_json):
        spec = _parse_llm_response(llm_json)
        assert len(spec.truth_graph.vulns) == 2
        vuln_ids = {v.id for v in spec.truth_graph.vulns}
        assert "VULN-SQLI-LOOKUP" in vuln_ids
        assert "VULN-MISSING-AUTHZ-REPORT" in vuln_ids

    def test_truth_graph_exploit_chain(self, llm_json):
        spec = _parse_llm_response(llm_json)
        assert len(spec.truth_graph.exploit_chain) == 2
        assert spec.truth_graph.exploit_chain[0].vuln_id == "VULN-SQLI-LOOKUP"

    def test_flags(self, llm_json):
        spec = _parse_llm_response(llm_json)
        assert len(spec.flags) == 2
        values = {f.value for f in spec.flags}
        assert "FLAG{9f3a2b4c5d6e7f80}" in values
        assert "FLAG{1a2b3c4d5e6f7788}" in values

    def test_golden_path(self, llm_json):
        spec = _parse_llm_response(llm_json)
        assert len(spec.golden_path) == 8
        # The real LLM output uses "cmd" field name
        assert spec.golden_path[0].command == "nmap -p 80 10.0.1.10"
        assert spec.golden_path[0].expect_in_stdout == "80/tcp open"
        assert spec.golden_path[0].host == "attacker"

    def test_task_briefings(self, llm_json):
        spec = _parse_llm_response(llm_json)
        assert "Meridian" in spec.task.red_briefing
        assert spec.task.blue_briefing != ""

    def test_npc_personas(self, llm_json):
        spec = _parse_llm_response(llm_json)
        assert len(spec.npc_personas) == 8
        names = {p.name for p in spec.npc_personas}
        assert "Derek Thompson" in names
        assert "Karen Williams" in names

    def test_npc_persona_security_awareness(self, llm_json):
        spec = _parse_llm_response(llm_json)
        by_name = {p.name: p for p in spec.npc_personas}
        assert by_name["Derek Thompson"].security_awareness == 0.85
        assert by_name["Karen Williams"].security_awareness == 0.25

    def test_files_dict(self, llm_json):
        spec = _parse_llm_response(llm_json)
        # Real LLM output has explicit files + vulnerable_code dicts
        assert len(spec.files) > 0
        assert "web:/var/www/portal/lookup.php" in spec.files
        assert "web:/var/www/portal/admin/compliance_report.php" in spec.files

    def test_vulnerable_code_as_dict_extracted_to_files(self, llm_json):
        spec = _parse_llm_response(llm_json)
        # The VULN-SQLI-LOOKUP has vulnerable_code as dict with key
        # /var/www/portal/lookup.php. It should be extracted to files
        # as "web:/var/www/portal/lookup.php".
        # But the explicit files dict already has this key, so the
        # explicit one takes precedence (container_key not in files check).
        assert "web:/var/www/portal/lookup.php" in spec.files


# ---------------------------------------------------------------------------
# 2. Field name mappings (ExploitStep aliases)
# ---------------------------------------------------------------------------


class TestExploitStepFieldMappings:
    """LLM uses vuln/action/yields; Pydantic expects vuln_id/command/description."""

    def test_vuln_maps_to_vuln_id(self):
        raw = _minimal_json(
            truth_graph={
                "vulns": [],
                "exploit_chain": [
                    {"vuln": "V1", "action": "run exploit", "yields": "root shell"}
                ],
            }
        )
        spec = _parse_llm_response(raw)
        assert spec.truth_graph.exploit_chain[0].vuln_id == "V1"

    def test_action_maps_to_command(self):
        raw = _minimal_json(
            truth_graph={
                "vulns": [],
                "exploit_chain": [
                    {"vuln": "V1", "action": "sqlmap -u http://...", "yields": "db dump"}
                ],
            }
        )
        spec = _parse_llm_response(raw)
        assert spec.truth_graph.exploit_chain[0].command == "sqlmap -u http://..."

    def test_yields_maps_to_description(self):
        raw = _minimal_json(
            truth_graph={
                "vulns": [],
                "exploit_chain": [
                    {"vuln": "V1", "action": "cmd", "yields": "got credentials"}
                ],
            }
        )
        spec = _parse_llm_response(raw)
        assert spec.truth_graph.exploit_chain[0].description == "got credentials"

    def test_canonical_names_also_work(self):
        """vuln_id/command/description should pass through without aliasing."""
        raw = _minimal_json(
            truth_graph={
                "vulns": [],
                "exploit_chain": [
                    {
                        "vuln_id": "V2",
                        "command": "nmap -sV ...",
                        "description": "port scan",
                    }
                ],
            }
        )
        spec = _parse_llm_response(raw)
        ec = spec.truth_graph.exploit_chain[0]
        assert ec.vuln_id == "V2"
        assert ec.command == "nmap -sV ..."
        assert ec.description == "port scan"

    def test_canonical_names_take_precedence(self):
        """When both canonical and alias are present, canonical wins (via get order)."""
        raw = _minimal_json(
            truth_graph={
                "vulns": [],
                "exploit_chain": [
                    {
                        "vuln_id": "canonical",
                        "vuln": "alias",
                        "command": "canonical_cmd",
                        "action": "alias_cmd",
                        "description": "canonical_desc",
                        "yields": "alias_desc",
                    }
                ],
            }
        )
        spec = _parse_llm_response(raw)
        ec = spec.truth_graph.exploit_chain[0]
        assert ec.vuln_id == "canonical"
        assert ec.command == "canonical_cmd"
        assert ec.description == "canonical_desc"


# ---------------------------------------------------------------------------
# 3. GoldenPathStep field mappings
# ---------------------------------------------------------------------------


class TestGoldenPathFieldMappings:
    """LLM uses cmd/expect_stdout; Pydantic expects command/expect_in_stdout."""

    def test_cmd_maps_to_command(self):
        raw = _minimal_json(
            golden_path=[
                {"step": 1, "cmd": "nmap -sV 10.0.1.0/24", "expect_stdout": "open"}
            ]
        )
        spec = _parse_llm_response(raw)
        assert spec.golden_path[0].command == "nmap -sV 10.0.1.0/24"

    def test_expect_stdout_maps_to_expect_in_stdout(self):
        raw = _minimal_json(
            golden_path=[
                {"step": 1, "cmd": "whoami", "expect_stdout": "root"}
            ]
        )
        spec = _parse_llm_response(raw)
        assert spec.golden_path[0].expect_in_stdout == "root"

    def test_canonical_command_field(self):
        raw = _minimal_json(
            golden_path=[
                {"step": 1, "command": "ls -la", "expect_in_stdout": "total"}
            ]
        )
        spec = _parse_llm_response(raw)
        assert spec.golden_path[0].command == "ls -la"
        assert spec.golden_path[0].expect_in_stdout == "total"

    def test_mixed_field_names_across_steps(self):
        """Some steps use cmd, others use command — both should parse."""
        raw = _minimal_json(
            golden_path=[
                {"step": 1, "cmd": "nmap scan", "expect_stdout": "80/tcp"},
                {"step": 2, "command": "curl http://web", "expect_in_stdout": "Welcome"},
                {"step": 3, "cmd": "sqlmap", "expect_in_stdout": "FLAG"},
            ]
        )
        spec = _parse_llm_response(raw)
        assert len(spec.golden_path) == 3
        assert spec.golden_path[0].command == "nmap scan"
        assert spec.golden_path[0].expect_in_stdout == "80/tcp"
        assert spec.golden_path[1].command == "curl http://web"
        assert spec.golden_path[1].expect_in_stdout == "Welcome"
        assert spec.golden_path[2].command == "sqlmap"
        assert spec.golden_path[2].expect_in_stdout == "FLAG"

    def test_step_number_preserved(self):
        raw = _minimal_json(
            golden_path=[
                {"step": 5, "cmd": "echo hi", "expect_stdout": "hi"}
            ]
        )
        spec = _parse_llm_response(raw)
        assert spec.golden_path[0].step == 5

    def test_description_field_preserved(self):
        raw = _minimal_json(
            golden_path=[
                {
                    "step": 1,
                    "cmd": "nmap",
                    "expect_stdout": "open",
                    "description": "Port scan the DMZ",
                }
            ]
        )
        spec = _parse_llm_response(raw)
        assert spec.golden_path[0].description == "Port scan the DMZ"

    def test_cmd_takes_precedence_over_command(self):
        """When both cmd and command are present, cmd wins (it's checked first)."""
        raw = _minimal_json(
            golden_path=[
                {
                    "step": 1,
                    "cmd": "cmd_value",
                    "command": "command_value",
                    "expect_stdout": "x",
                }
            ]
        )
        spec = _parse_llm_response(raw)
        assert spec.golden_path[0].command == "cmd_value"


# ---------------------------------------------------------------------------
# 4. Evidence spec parsing
# ---------------------------------------------------------------------------


class TestEvidenceSpecParsing:
    """LLM returns dict, protocol expects list[EvidenceItem]."""

    def test_dict_with_string_values(self):
        raw = _minimal_json(
            evidence_spec={
                "web_access_log": "SQL injection pattern",
                "siem_alerts": "Unauthorized access",
            }
        )
        spec = _parse_llm_response(raw)
        assert len(spec.evidence_spec) == 2
        locations = {e.location for e in spec.evidence_spec}
        assert "web_access_log" in locations
        assert "siem_alerts" in locations
        # String values become log_entry type
        for e in spec.evidence_spec:
            if e.location == "web_access_log":
                assert e.type == "log_entry"
                assert e.pattern == "SQL injection pattern"

    def test_dict_with_list_values(self):
        raw = _minimal_json(
            evidence_spec={
                "siem_alerts": ["UNION SELECT detected", "admin endpoint accessed"],
            }
        )
        spec = _parse_llm_response(raw)
        assert len(spec.evidence_spec) == 2
        # List values become alert type
        for e in spec.evidence_spec:
            assert e.type == "alert"
            assert e.location == "siem_alerts"
        patterns = {e.pattern for e in spec.evidence_spec}
        assert "UNION SELECT detected" in patterns
        assert "admin endpoint accessed" in patterns

    def test_dict_with_mixed_values(self):
        raw = _minimal_json(
            evidence_spec={
                "web_log": "GET /search?q=",
                "alerts": ["sqli_detected", "auth_bypass"],
            }
        )
        spec = _parse_llm_response(raw)
        assert len(spec.evidence_spec) == 3  # 1 string + 2 list items

    def test_list_format_passthrough(self):
        """When evidence_spec is already a list of dicts, parse directly."""
        raw = _minimal_json(
            evidence_spec=[
                {"type": "alert", "location": "siem", "pattern": "SQLi"},
                {"type": "log_entry", "location": "web_log", "pattern": "GET /admin"},
            ]
        )
        spec = _parse_llm_response(raw)
        assert len(spec.evidence_spec) == 2
        assert spec.evidence_spec[0].type == "alert"
        assert spec.evidence_spec[1].location == "web_log"

    def test_empty_dict(self):
        raw = _minimal_json(evidence_spec={})
        spec = _parse_llm_response(raw)
        assert spec.evidence_spec == []

    def test_empty_list(self):
        raw = _minimal_json(evidence_spec=[])
        spec = _parse_llm_response(raw)
        assert spec.evidence_spec == []


# ---------------------------------------------------------------------------
# 5. NPC persona parsing
# ---------------------------------------------------------------------------


class TestNPCPersonaParsing:
    def test_basic_persona(self):
        raw = _minimal_json(
            npc_personas=[
                {
                    "name": "Alice",
                    "role": "Admin",
                    "department": "IT",
                    "security_awareness": 0.9,
                }
            ]
        )
        spec = _parse_llm_response(raw)
        assert len(spec.npc_personas) == 1
        p = spec.npc_personas[0]
        assert p.name == "Alice"
        assert p.role == "Admin"
        assert p.department == "IT"
        assert p.security_awareness == 0.9

    def test_accounts_with_string_values(self):
        raw = _minimal_json(
            npc_personas=[
                {
                    "name": "Bob",
                    "accounts": {
                        "email": "bob@corp.local",
                        "ldap_dn": "cn=bob,dc=corp,dc=local",
                    },
                }
            ]
        )
        spec = _parse_llm_response(raw)
        assert spec.npc_personas[0].accounts["email"] == "bob@corp.local"

    def test_default_security_awareness(self):
        """Missing security_awareness defaults to 0.5."""
        raw = _minimal_json(npc_personas=[{"name": "Charlie"}])
        spec = _parse_llm_response(raw)
        assert spec.npc_personas[0].security_awareness == 0.5

    def test_susceptibility_dict(self):
        raw = _minimal_json(
            npc_personas=[
                {
                    "name": "Diana",
                    "susceptibility": {"phishing": 0.8, "pretexting": 0.6},
                }
            ]
        )
        spec = _parse_llm_response(raw)
        assert spec.npc_personas[0].susceptibility["phishing"] == 0.8

    def test_routine_dict(self):
        raw = _minimal_json(
            npc_personas=[
                {
                    "name": "Eve",
                    "routine": {
                        "morning": "check email",
                        "afternoon": "process reports",
                    },
                }
            ]
        )
        spec = _parse_llm_response(raw)
        assert spec.npc_personas[0].routine["morning"] == "check email"

    def test_multiple_personas(self):
        raw = _minimal_json(
            npc_personas=[
                {"name": "P1", "security_awareness": 0.1},
                {"name": "P2", "security_awareness": 0.5},
                {"name": "P3", "security_awareness": 0.9},
            ]
        )
        spec = _parse_llm_response(raw)
        assert len(spec.npc_personas) == 3
        names = [p.name for p in spec.npc_personas]
        assert names == ["P1", "P2", "P3"]

    def test_missing_optional_fields_default(self):
        """All optional fields should default gracefully."""
        raw = _minimal_json(npc_personas=[{"name": "Minimal"}])
        spec = _parse_llm_response(raw)
        p = spec.npc_personas[0]
        assert p.name == "Minimal"
        assert p.role == ""
        assert p.department == ""
        assert p.reports_to == ""
        assert p.communication_style == ""
        assert p.susceptibility == {}
        assert p.routine == {}
        assert p.accounts == {}


# ---------------------------------------------------------------------------
# 6. Files dict extraction
# ---------------------------------------------------------------------------


class TestFilesDictExtraction:
    def test_explicit_files_field(self):
        raw = _minimal_json(
            files={
                "web:/var/www/index.php": "<?php echo 'hello'; ?>",
                "db:/opt/init.sql": "CREATE TABLE t(id INT);",
            }
        )
        spec = _parse_llm_response(raw)
        assert len(spec.files) == 2
        assert spec.files["web:/var/www/index.php"] == "<?php echo 'hello'; ?>"

    def test_vulnerable_code_dict_extracted(self):
        """vulnerable_code as {file_path: code} should be extracted to files."""
        raw = _minimal_json(
            truth_graph={
                "vulns": [
                    {
                        "id": "v1",
                        "type": "sqli",
                        "host": "web",
                        "service": "php",
                        "injection_point": "/search",
                        "vulnerable_code": {
                            "/var/www/search.php": "<?php $q=$_GET['q']; ?>"
                        },
                    }
                ],
                "exploit_chain": [],
            }
        )
        spec = _parse_llm_response(raw)
        assert "web:/var/www/search.php" in spec.files
        assert spec.files["web:/var/www/search.php"] == "<?php $q=$_GET['q']; ?>"

    def test_vulnerable_code_string_on_web_host(self):
        """String vulnerable_code on web host with / injection_point goes to web:/var/www/portal{ip}."""
        raw = _minimal_json(
            truth_graph={
                "vulns": [
                    {
                        "id": "v1",
                        "type": "sqli",
                        "host": "web",
                        "service": "php",
                        "injection_point": "/search.php",
                        "vulnerable_code": "<?php echo 'vuln'; ?>",
                    }
                ],
                "exploit_chain": [],
            }
        )
        spec = _parse_llm_response(raw)
        assert "web:/var/www/portal/search.php" in spec.files

    def test_vulnerable_code_string_non_web_host_skipped(self):
        """String vulnerable_code on non-web host without / prefix is not extracted."""
        raw = _minimal_json(
            truth_graph={
                "vulns": [
                    {
                        "id": "v1",
                        "type": "weak_creds",
                        "host": "db",
                        "service": "mysql",
                        "injection_point": "mysql -u root -proot",
                        "vulnerable_code": "",
                    }
                ],
                "exploit_chain": [],
            }
        )
        spec = _parse_llm_response(raw)
        assert len(spec.files) == 0

    def test_explicit_files_not_overwritten_by_vulnerable_code(self):
        """If explicit files has a key, vulnerable_code should not overwrite it."""
        raw = _minimal_json(
            files={"web:/var/www/search.php": "explicit content"},
            truth_graph={
                "vulns": [
                    {
                        "id": "v1",
                        "type": "sqli",
                        "host": "web",
                        "service": "php",
                        "injection_point": "/search",
                        "vulnerable_code": {
                            "/var/www/search.php": "vulnerable content"
                        },
                    }
                ],
                "exploit_chain": [],
            },
        )
        spec = _parse_llm_response(raw)
        assert spec.files["web:/var/www/search.php"] == "explicit content"

    def test_no_files_field_produces_empty_dict(self):
        raw = _minimal_json()
        spec = _parse_llm_response(raw)
        assert spec.files == {}

    def test_files_field_non_string_values_skipped(self):
        """Non-string values in files dict are silently skipped."""
        raw = _minimal_json(
            files={
                "web:/good.php": "<?php ?>",
                "web:/bad.php": 12345,
                "web:/also_bad.php": ["not", "a", "string"],
            }
        )
        spec = _parse_llm_response(raw)
        assert len(spec.files) == 1
        assert "web:/good.php" in spec.files


# ---------------------------------------------------------------------------
# 7. Missing optional fields
# ---------------------------------------------------------------------------


class TestMissingOptionalFields:
    def test_missing_evidence_spec(self):
        data = {
            "topology": {},
            "truth_graph": {"vulns": [], "exploit_chain": []},
            "golden_path": [],
            "flags": [],
            "npc_personas": [],
            "npc_traffic": {},
            "task": {},
        }
        spec = _parse_llm_response(json.dumps(data))
        assert spec.evidence_spec == []

    def test_missing_npc_personas(self):
        data = {
            "topology": {},
            "truth_graph": {"vulns": [], "exploit_chain": []},
            "golden_path": [],
            "flags": [],
            "evidence_spec": {},
            "npc_traffic": {},
            "task": {},
        }
        spec = _parse_llm_response(json.dumps(data))
        assert spec.npc_personas == []

    def test_missing_npc_traffic(self):
        data = {
            "topology": {},
            "truth_graph": {"vulns": [], "exploit_chain": []},
            "golden_path": [],
            "flags": [],
            "evidence_spec": {},
            "npc_personas": [],
            "task": {},
        }
        spec = _parse_llm_response(json.dumps(data))
        # npc_traffic gets default NPCTrafficSpec values
        assert spec.npc_traffic.level == 0

    def test_missing_task(self):
        data = {
            "topology": {},
            "truth_graph": {"vulns": [], "exploit_chain": []},
            "golden_path": [],
            "flags": [],
            "evidence_spec": {},
            "npc_personas": [],
            "npc_traffic": {},
        }
        spec = _parse_llm_response(json.dumps(data))
        assert spec.task.red_briefing == ""
        assert spec.task.blue_briefing == ""

    def test_missing_truth_graph(self):
        data = {
            "topology": {"hosts": ["web"]},
            "golden_path": [],
            "flags": [],
            "evidence_spec": {},
            "npc_personas": [],
            "npc_traffic": {},
            "task": {},
        }
        spec = _parse_llm_response(json.dumps(data))
        assert spec.truth_graph.vulns == []
        assert spec.truth_graph.exploit_chain == []

    def test_missing_golden_path(self):
        data = {
            "topology": {},
            "truth_graph": {"vulns": [], "exploit_chain": []},
            "flags": [],
            "evidence_spec": {},
            "npc_personas": [],
            "npc_traffic": {},
            "task": {},
        }
        spec = _parse_llm_response(json.dumps(data))
        assert spec.golden_path == []

    def test_missing_flags(self):
        data = {
            "topology": {},
            "truth_graph": {"vulns": [], "exploit_chain": []},
            "golden_path": [],
            "evidence_spec": {},
            "npc_personas": [],
            "npc_traffic": {},
            "task": {},
        }
        spec = _parse_llm_response(json.dumps(data))
        assert spec.flags == []

    def test_vuln_with_minimal_fields(self):
        """A vulnerability with only id, type, host should parse fine."""
        raw = _minimal_json(
            truth_graph={
                "vulns": [{"id": "v1", "type": "sqli", "host": "web"}],
                "exploit_chain": [],
            }
        )
        spec = _parse_llm_response(raw)
        v = spec.truth_graph.vulns[0]
        assert v.id == "v1"
        assert v.service == ""
        assert v.injection_point == ""
        assert v.vulnerable_code == ""
        assert v.root_cause == ""


# ---------------------------------------------------------------------------
# 8. Empty/minimal input
# ---------------------------------------------------------------------------


class TestMinimalInput:
    def test_completely_empty_json_object(self):
        """An empty JSON object should produce a valid SnapshotSpec with defaults."""
        spec = _parse_llm_response("{}")
        assert isinstance(spec, SnapshotSpec)
        assert spec.topology == {}
        assert spec.truth_graph.vulns == []
        assert spec.golden_path == []
        assert spec.flags == []
        assert spec.evidence_spec == []
        assert spec.npc_personas == []

    def test_minimal_valid_json(self):
        raw = _minimal_json()
        spec = _parse_llm_response(raw)
        assert isinstance(spec, SnapshotSpec)

    def test_topology_only(self):
        raw = json.dumps({"topology": {"hosts": ["web", "db"]}})
        spec = _parse_llm_response(raw)
        assert spec.topology["hosts"] == ["web", "db"]
        assert spec.golden_path == []


# ---------------------------------------------------------------------------
# 9. Malformed input
# ---------------------------------------------------------------------------


class TestMalformedInput:
    def test_invalid_json_raises(self):
        with pytest.raises(json.JSONDecodeError):
            _parse_llm_response("not valid json {{{")

    def test_json_array_not_object_raises(self):
        """Top-level must be an object, not an array."""
        with pytest.raises((TypeError, AttributeError, SnapshotParseError)):
            _parse_llm_response("[1, 2, 3]")

    def test_json_string_not_object_raises(self):
        with pytest.raises((TypeError, AttributeError, SnapshotParseError)):
            _parse_llm_response('"just a string"')

    def test_truth_graph_not_dict_handled(self):
        """If truth_graph is a non-dict, parsing should fail gracefully."""
        # truth_graph as string
        raw = json.dumps({"truth_graph": "not a dict"})
        with pytest.raises((AttributeError, SnapshotParseError)):
            _parse_llm_response(raw)

    def test_golden_path_not_list_handled(self):
        """If golden_path is a non-list, parsing should fail gracefully."""
        raw = json.dumps({"golden_path": "not a list"})
        with pytest.raises((AttributeError, SnapshotParseError)):
            _parse_llm_response(raw)

    def test_empty_string_raises(self):
        with pytest.raises(json.JSONDecodeError):
            _parse_llm_response("")

    def test_json_with_trailing_comma_raises(self):
        with pytest.raises(json.JSONDecodeError):
            _parse_llm_response('{"key": "value",}')


# ---------------------------------------------------------------------------
# 10. Vulnerability parsing details
# ---------------------------------------------------------------------------


class TestVulnerabilityParsing:
    def test_all_vuln_fields_parsed(self):
        raw = _minimal_json(
            truth_graph={
                "vulns": [
                    {
                        "id": "VULN-001",
                        "type": "sqli",
                        "host": "web",
                        "service": "nginx+php",
                        "injection_point": "/search?q=",
                        "vulnerable_code": "<?php $q=$_GET['q']; ?>",
                        "root_cause": "No input sanitization",
                        "blast_radius": "Full DB read",
                        "remediation": "Use prepared statements",
                    }
                ],
                "exploit_chain": [],
            }
        )
        spec = _parse_llm_response(raw)
        v = spec.truth_graph.vulns[0]
        assert v.id == "VULN-001"
        assert v.type == "sqli"
        assert v.host == "web"
        assert v.service == "nginx+php"
        assert v.injection_point == "/search?q="
        assert v.vulnerable_code == "<?php $q=$_GET['q']; ?>"
        assert v.root_cause == "No input sanitization"
        assert v.blast_radius == "Full DB read"
        assert v.remediation == "Use prepared statements"

    def test_vulnerable_code_as_dict(self):
        raw = _minimal_json(
            truth_graph={
                "vulns": [
                    {
                        "id": "V1",
                        "type": "sqli",
                        "host": "web",
                        "vulnerable_code": {
                            "/var/www/search.php": "<?php vuln code; ?>"
                        },
                    }
                ],
                "exploit_chain": [],
            }
        )
        spec = _parse_llm_response(raw)
        v = spec.truth_graph.vulns[0]
        assert isinstance(v.vulnerable_code, dict)
        assert v.vulnerable_code["/var/www/search.php"] == "<?php vuln code; ?>"

    def test_multiple_vulns(self):
        raw = _minimal_json(
            truth_graph={
                "vulns": [
                    {"id": "V1", "type": "sqli", "host": "web"},
                    {"id": "V2", "type": "xss", "host": "web"},
                    {"id": "V3", "type": "idor", "host": "web"},
                ],
                "exploit_chain": [],
            }
        )
        spec = _parse_llm_response(raw)
        assert len(spec.truth_graph.vulns) == 3
        types = {v.type for v in spec.truth_graph.vulns}
        assert types == {"sqli", "xss", "idor"}


# ---------------------------------------------------------------------------
# 11. Flag parsing
# ---------------------------------------------------------------------------


class TestFlagParsing:
    def test_single_flag(self):
        raw = _minimal_json(
            flags=[
                {
                    "id": "flag1",
                    "value": "FLAG{abc123}",
                    "path": "/var/flags/flag1.txt",
                    "host": "db",
                }
            ]
        )
        spec = _parse_llm_response(raw)
        assert len(spec.flags) == 1
        f = spec.flags[0]
        assert f.id == "flag1"
        assert f.value == "FLAG{abc123}"
        assert f.path == "/var/flags/flag1.txt"
        assert f.host == "db"

    def test_multiple_flags(self):
        raw = _minimal_json(
            flags=[
                {"id": "f1", "value": "FLAG{a}", "path": "/f1.txt", "host": "web"},
                {"id": "f2", "value": "FLAG{b}", "path": "/f2.txt", "host": "db"},
            ]
        )
        spec = _parse_llm_response(raw)
        assert len(spec.flags) == 2

    def test_missing_flag_fields_default_to_empty(self):
        raw = _minimal_json(flags=[{}])
        spec = _parse_llm_response(raw)
        f = spec.flags[0]
        assert f.id == ""
        assert f.value == ""
        assert f.path == ""
        assert f.host == ""


# ---------------------------------------------------------------------------
# 12. NPC traffic parsing
# ---------------------------------------------------------------------------


class TestNPCTrafficParsing:
    def test_http_rate_maps_to_rate_lambda(self):
        raw = _minimal_json(npc_traffic={"http_rate": 25})
        spec = _parse_llm_response(raw)
        assert spec.npc_traffic.rate_lambda == 25

    def test_default_scripts(self):
        raw = _minimal_json(npc_traffic={})
        spec = _parse_llm_response(raw)
        assert "http_traffic.sh" in spec.npc_traffic.scripts

    def test_level_always_zero(self):
        """Current parser hardcodes level=0."""
        raw = _minimal_json(npc_traffic={"http_rate": 50})
        spec = _parse_llm_response(raw)
        assert spec.npc_traffic.level == 0

    def test_missing_http_rate_defaults_to_10(self):
        raw = _minimal_json(npc_traffic={})
        spec = _parse_llm_response(raw)
        assert spec.npc_traffic.rate_lambda == 10


# ---------------------------------------------------------------------------
# 13. Task parsing
# ---------------------------------------------------------------------------


class TestTaskParsing:
    def test_both_briefings(self):
        raw = _minimal_json(
            task={
                "red_briefing": "Attack the network.",
                "blue_briefing": "Defend the network.",
            }
        )
        spec = _parse_llm_response(raw)
        assert spec.task.red_briefing == "Attack the network."
        assert spec.task.blue_briefing == "Defend the network."

    def test_missing_briefings_default_empty(self):
        raw = _minimal_json(task={})
        spec = _parse_llm_response(raw)
        assert spec.task.red_briefing == ""
        assert spec.task.blue_briefing == ""

    def test_extra_task_fields_ignored(self):
        """Extra fields in task should be silently ignored."""
        raw = _minimal_json(
            task={
                "red_briefing": "Go",
                "blue_briefing": "Watch",
                "unknown_field": "whatever",
            }
        )
        spec = _parse_llm_response(raw)
        assert spec.task.red_briefing == "Go"


# ---------------------------------------------------------------------------
# 14. Roundtrip / integration
# ---------------------------------------------------------------------------


class TestRoundtrip:
    def test_complex_snapshot_parses_completely(self):
        """A complex snapshot with all sections populated should parse."""
        data = {
            "topology": {
                "hosts": ["attacker", "web", "db", "siem"],
                "zones": {"dmz": ["web"], "internal": ["db"], "mgmt": ["siem"]},
                "users": [{"username": "admin", "password": "pass", "groups": ["admins"], "hosts": ["web"]}],
            },
            "truth_graph": {
                "vulns": [
                    {
                        "id": "V1",
                        "type": "sqli",
                        "host": "web",
                        "service": "php",
                        "injection_point": "/search?q=",
                        "vulnerable_code": {"search.php": "vuln code"},
                        "root_cause": "no sanitization",
                        "blast_radius": "db read",
                        "remediation": "prepared stmts",
                    }
                ],
                "exploit_chain": [
                    {"vuln": "V1", "action": "sqlmap", "yields": "db dump"}
                ],
            },
            "golden_path": [
                {"step": 1, "cmd": "nmap -sV 10.0.1.0/24", "expect_stdout": "80/tcp"},
                {"step": 2, "command": "curl http://web/search?q=test", "expect_in_stdout": "results"},
            ],
            "flags": [
                {"id": "f1", "value": "FLAG{complex}", "path": "/flag.txt", "host": "db"}
            ],
            "evidence_spec": {
                "web_log": "sqli pattern",
                "alerts": ["sql_injection_detected"],
            },
            "npc_personas": [
                {
                    "name": "Alice",
                    "role": "SysAdmin",
                    "department": "IT",
                    "reports_to": "CTO",
                    "communication_style": "technical",
                    "security_awareness": 0.9,
                    "susceptibility": {"phishing": 0.1},
                    "routine": {"morning": "check logs"},
                    "accounts": {"email": "alice@corp.local"},
                }
            ],
            "npc_traffic": {"http_rate": 20},
            "task": {
                "red_briefing": "Hack the network.",
                "blue_briefing": "Monitor and defend.",
            },
            "files": {"web:/var/www/index.php": "<?php echo 'hi'; ?>"},
        }
        spec = _parse_llm_response(json.dumps(data))

        # Verify all sections
        assert spec.topology["hosts"] == ["attacker", "web", "db", "siem"]
        assert len(spec.truth_graph.vulns) == 1
        assert spec.truth_graph.exploit_chain[0].vuln_id == "V1"
        assert spec.truth_graph.exploit_chain[0].command == "sqlmap"
        assert len(spec.golden_path) == 2
        assert spec.golden_path[0].command == "nmap -sV 10.0.1.0/24"
        assert spec.golden_path[1].expect_in_stdout == "results"
        assert spec.flags[0].value == "FLAG{complex}"
        assert len(spec.evidence_spec) == 2  # 1 string + 1 list item
        assert len(spec.npc_personas) == 1
        assert spec.npc_traffic.rate_lambda == 20
        assert spec.task.red_briefing == "Hack the network."
        # files: explicit + vulnerable_code dict
        assert "web:/var/www/index.php" in spec.files

    def test_golden_path_host_is_preserved(self):
        raw = _minimal_json(
            golden_path=[
                {
                    "step": 1,
                    "cmd": "ssh db 'cat /var/flags/flag1.txt'",
                    "expect_stdout": "FLAG{db}",
                    "host": "jumpbox",
                }
            ]
        )
        spec = _parse_llm_response(raw)
        assert spec.golden_path[0].host == "jumpbox"
