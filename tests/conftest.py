"""Shared fixtures for OpenRange test suite."""

from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent


@pytest.fixture
def manifests_dir():
    return ROOT / "manifests"


@pytest.fixture
def tier1_manifest(manifests_dir):
    """Load tier1_basic.yaml as dict."""
    import yaml

    with open(manifests_dir / "tier1_basic.yaml") as f:
        return yaml.safe_load(f)


@pytest.fixture
def tier2_manifest(manifests_dir):
    """Load tier2_corporate.yaml as dict."""
    import yaml

    with open(manifests_dir / "tier2_corporate.yaml") as f:
        return yaml.safe_load(f)


@pytest.fixture
def tier3_manifest(manifests_dir):
    """Load tier3_enterprise.yaml as dict."""
    import yaml

    with open(manifests_dir / "tier3_enterprise.yaml") as f:
        return yaml.safe_load(f)


@pytest.fixture
def sample_snapshot_spec():
    """A valid SnapshotSpec for testing."""
    from open_range.protocols import (
        EvidenceItem,
        FlagSpec,
        GoldenPathStep,
        NPCTrafficSpec,
        SnapshotSpec,
        TaskSpec,
        TruthGraph,
        Vulnerability,
    )

    return SnapshotSpec(
        topology={
            "hosts": [
                "attacker", "firewall", "web", "mail",
                "db", "files", "ldap", "siem",
            ],
            "zones": {
                "external": ["attacker"],
                "dmz": ["web", "mail"],
                "internal": ["db", "files"],
                "management": ["ldap", "siem"],
            },
            "users": [
                {
                    "username": "admin",
                    "password": "admin123",
                    "groups": ["admins"],
                    "hosts": ["web", "db"],
                }
            ],
            "tier": 1,
        },
        truth_graph=TruthGraph(
            vulns=[
                Vulnerability(
                    id="vuln1",
                    type="sqli",
                    host="web",
                    service="php",
                    injection_point="/search?q=",
                    vulnerable_code=(
                        "$conn->query(\"SELECT * FROM products "
                        "WHERE name LIKE '%$_GET[q]%'\");"
                    ),
                    root_cause="Unsanitized input in SQL query",
                    blast_radius="data exposure",
                    remediation="Use parameterized queries",
                )
            ],
            exploit_chain=[],
        ),
        flags=[
            FlagSpec(
                id="flag1",
                value="FLAG{test_sqli_123}",
                path="/var/flags/flag1.txt",
                host="db",
            )
        ],
        golden_path=[
            GoldenPathStep(
                step=1,
                command="nmap -sV 10.0.1.0/24",
                expect_in_stdout="80/tcp open http",
            ),
            GoldenPathStep(
                step=2,
                command="curl 'http://web/search?q=test'",
                expect_in_stdout="products",
            ),
            GoldenPathStep(
                step=3,
                command=(
                    "curl 'http://web/search?q=test%27+UNION+"
                    "SELECT+flag+FROM+flags--'"
                ),
                expect_in_stdout="FLAG{test_sqli_123}",
            ),
            GoldenPathStep(
                step=4,
                command="nmap -sV 10.0.2.0/24",
                expect_in_stdout="3306/tcp open mysql",
            ),
            GoldenPathStep(
                step=5,
                command="curl http://web/",
                expect_in_stdout="Welcome",
            ),
            GoldenPathStep(
                step=6,
                command="curl http://web/login",
                expect_in_stdout="Login",
            ),
            GoldenPathStep(
                step=7,
                command="mysql -h db -u admin -padmin123 -e 'SHOW DATABASES'",
                expect_in_stdout="flags",
            ),
            GoldenPathStep(
                step=8,
                command="submit_flag FLAG{test_sqli_123}",
                expect_in_stdout="correct",
            ),
        ],
        evidence_spec=[
            EvidenceItem(
                type="log_entry",
                location="web_access_log",
                pattern="SQL injection pattern in access log",
            )
        ],
        npc_traffic=NPCTrafficSpec(level=0, rate_lambda=30.0),
        npc_personas=[],
        task=TaskSpec(
            red_briefing=(
                "Target network has web services. Find vulnerabilities "
                "and capture the flag."
            ),
            blue_briefing=(
                "Monitor SIEM for suspicious activity. Investigate "
                "and respond to threats."
            ),
        ),
    )


@pytest.fixture
def mock_containers():
    """Mock ContainerSet for testing without Docker."""

    class MockContainerSet:
        def __init__(self):
            self.exec_results = {}  # {(container, cmd_fragment): output}
            self.healthy = set()

        async def exec(self, container: str, cmd: str, **kwargs) -> str:
            for (c, pattern), result in self.exec_results.items():
                if c == container and pattern in cmd:
                    return result
            return ""

        async def is_healthy(self, container: str) -> bool:
            return container in self.healthy

        async def cp(self, container, src, dest):
            pass

    return MockContainerSet()
