"""NPC action executor -- bridges NPC decisions to container state changes.

All actions are derived from the SnapshotSpec at init time, so they adapt
to whatever environment the Builder LLM generated.  No hardcoded pages,
tables, or endpoints.
"""

from __future__ import annotations

import logging
import random
import re
import shlex
import time
from typing import Any

from open_range.builder.npc.npc_agent import NPCAction
from open_range.contracts.world import GreenPersona

# ---------------------------------------------------------------------------
# Realistic user-agent pool  (DoD #5 — green traffic harder to fingerprint)
# ---------------------------------------------------------------------------

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/124.0",
]

_HTTP_STATUS_WEIGHTS = [
    (200, 0.75),
    (200, 0.05),
    (301, 0.05),
    (304, 0.08),
    (404, 0.05),
    (403, 0.02),
]
_HTTP_STATUSES = [s for s, _ in _HTTP_STATUS_WEIGHTS]
_HTTP_WEIGHTS = [w for _, w in _HTTP_STATUS_WEIGHTS]


def _random_ua() -> str:
    return random.choice(_USER_AGENTS)


def _random_status() -> int:
    return random.choices(_HTTP_STATUSES, weights=_HTTP_WEIGHTS, k=1)[0]


def _random_bytes(lo: int = 512, hi: int = 65536) -> int:
    return random.randint(lo, hi)


# Type aliases for container/snapshot objects (duck-typed at runtime)
ContainerSet = Any
SnapshotSpec = Any
NPCPersona = GreenPersona  # backwards-compat alias within this module

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Host resolution -- resolve logical roles to actual topology hostnames
# ---------------------------------------------------------------------------


def _resolve_host(
    snapshot: SnapshotSpec,
    keywords: list[str],
    fallback: str,
) -> str:
    """Resolve a logical role to an actual hostname from the snapshot topology.

    Searches ``snapshot.topology["hosts"]`` for a host whose name or services
    match any of the given *keywords*.  Returns the first match, or *fallback*
    if the topology is empty or no match is found.

    This mirrors the keyword-matching pattern used in ``npc_manager.py``
    (``_host_matches_keywords`` / ``_ROLE_SERVICE_KEYWORDS``).
    """
    hosts = snapshot.topology.get("hosts") or []
    for host in hosts:
        if isinstance(host, str):
            # Plain string host name -- match against keywords directly
            host_lower = host.lower()
            for kw in keywords:
                if kw.lower() in host_lower:
                    return host
            continue
        if not isinstance(host, dict):
            continue
        host_name = (host.get("name") or "").lower()
        services = [s.lower() for s in (host.get("services") or [])]
        for kw in keywords:
            kw_lower = kw.lower()
            if kw_lower in host_name or any(kw_lower in svc for svc in services):
                return host.get("name", fallback)
    return fallback


# ---------------------------------------------------------------------------
# NPC source resolution -- determine which container a persona "sits at"
# ---------------------------------------------------------------------------


def _resolve_npc_source(persona: NPCPersona, snapshot: SnapshotSpec) -> str:
    """Pick the container a persona originates traffic from.

    NPCs are people — their traffic should cross the Docker network.
    Uses ``siem`` as the default workstation since it exists in every tier
    and sits in the management zone where employee workstations would be.
    """
    return "siem"


class NPCActionExecutor:
    """Execute NPC actions inside Docker containers.

    At init, extracts available pages, shares, DB tables, users, and
    credentials from the snapshot so every action targets real resources
    in this environment.  Container names are resolved from the snapshot
    topology via keyword matching, so the executor works with any host
    naming convention (not just the default tier-1 names).
    """

    def __init__(self, containers: ContainerSet, snapshot: SnapshotSpec) -> None:
        self.containers = containers
        self._snapshot = snapshot
        # Derive available targets from the snapshot
        self._pages = _extract_web_pages(snapshot)
        self._shares = _extract_shares(snapshot)
        self._db_tables = _extract_db_tables(snapshot)
        self._users = _extract_users(snapshot)
        self._domain = snapshot.topology.get("domain", "corp.local")
        self._db_creds = _extract_db_credentials(snapshot)
        self._ssh_creds = _extract_ssh_credentials(snapshot)

        # Resolve logical roles to actual hostnames from the topology
        self._host_web = _resolve_host(
            snapshot, ["nginx", "apache", "httpd", "web", "php-fpm"], "web"
        )
        self._host_mail = _resolve_host(
            snapshot, ["postfix", "sendmail", "dovecot", "mail"], "mail"
        )
        self._host_db = _resolve_host(
            snapshot, ["mysql", "mariadb", "postgres", "mongodb"], "db"
        )
        self._host_siem = _resolve_host(
            snapshot, ["rsyslog", "elasticsearch", "siem", "splunk"], "siem"
        )
        self._host_files = _resolve_host(
            snapshot, ["samba", "smb", "files", "nfs"], "files"
        )

        # NPC source containers -- maps persona name -> source container.
        # Lazily populated by source_for() as personas are encountered.
        self._source_hosts: dict[str, str] = {}

    def source_for(self, persona: NPCPersona) -> str:
        """Return the source container for a persona (their "workstation").

        Results are cached per persona name.  NPCs originate network traffic
        from this container and target services by hostname across the Docker
        network, so that traffic is visible on the wire.
        """
        name = persona.id
        if name not in self._source_hosts:
            self._source_hosts[name] = _resolve_npc_source(persona, self._snapshot)
        return self._source_hosts[name]

    # ------------------------------------------------------------------
    # Routine actions (autonomous workday)
    # ------------------------------------------------------------------

    async def execute_routine(
        self,
        persona: NPCPersona,
        action: str,
        target: str,
        detail: str,
        email_body: str = "",
    ) -> dict[str, Any]:
        """Execute an autonomous work action derived from the snapshot."""
        username = _username_from_persona(persona)

        handler = {
            "browse": self._routine_browse,
            "send_email": self._routine_email,
            "lookup": self._routine_lookup,
            "access_share": self._routine_share,
            "login": self._routine_login,
            "query_db": self._routine_query_db,
            "idle": self._routine_idle,
        }.get(action, self._routine_idle)

        return await handler(persona, username, target, detail, email_body)

    async def _routine_browse(self, persona, username, target, detail, _eb):
        """Browse a page that exists in this snapshot.

        Executes from the persona's source container, targeting the web
        server by hostname across the Docker network.
        """
        path = target if target.startswith("/") else f"/{target}" if target else "/"
        if path == "/" and self._pages:
            path = random.choice(self._pages)
        safe_path = shlex.quote(f"http://{self._host_web}{path}")
        ua = _random_ua()
        safe_ua = shlex.quote(ua)
        source = self.source_for(persona)
        await self.containers.exec(
            source,
            f"curl -s -o /dev/null -A {safe_ua} {safe_path}",
        )
        return _web_log(persona, "browse", detail or f"Browsed {path}", path, ua)

    async def _routine_email(self, persona, username, target, detail, body):
        """Send email to a colleague (picks a real user from topology).

        Delivers to both the sender's sent folder and the recipient's inbox
        so the receiving NPC can read it during their mailbox check.
        Logs as type 'npc_chat' (DoD #4).
        """
        recipient = target
        if not recipient and self._users:
            recipient = random.choice(self._users)
        elif not recipient:
            recipient = "colleague"

        ts_i = int(time.time())
        content = body or f"Hi {recipient}, quick update: {detail or 'checking in'}."
        msg = (
            f"From: {username}@{self._domain}\\n"
            f"To: {recipient}@{self._domain}\\n"
            f"Subject: {detail or 'Update'}\\n\\n{content}"
        )
        safe_user = shlex.quote(username)
        safe_recipient = shlex.quote(recipient)
        safe_msg = shlex.quote(msg)
        # Sender's sent folder
        await self.containers.exec(
            self._host_mail,
            f"mkdir -p /var/mail/{safe_user} "
            f"&& echo {safe_msg} > /var/mail/{safe_user}/sent_{ts_i}.eml",
        )
        # Recipient's inbox (DoD #4 — NPC-to-NPC delivery)
        await self.containers.exec(
            self._host_mail,
            f"mkdir -p /var/mail/{safe_recipient} "
            f"&& echo {safe_msg} > /var/mail/{safe_recipient}/inbox_{ts_i}.eml",
        )
        return _chat_log(
            persona, recipient, detail or f"Message to {recipient}", f"mail:{username}"
        )

    async def _routine_lookup(self, persona, username, target, detail, _eb):
        """Look up data on the web app -- uses whatever search/lookup page exists.

        Executes from the persona's source container, targeting the web
        server by hostname across the Docker network.
        """
        lookup_pages = [
            p for p in self._pages if "?" in p or "lookup" in p or "search" in p
        ]
        if lookup_pages:
            page = random.choice(lookup_pages)
        elif self._pages:
            page = random.choice(self._pages) + "?q=" + (target or "status")
        else:
            page = f"/?q={target or 'data'}"

        ua = _random_ua()
        safe_url = shlex.quote(f"http://{self._host_web}{page}")
        safe_ua = shlex.quote(ua)
        source = self.source_for(persona)
        await self.containers.exec(
            source,
            f"curl -s -o /dev/null -A {safe_ua} {safe_url}",
        )
        return _web_log(persona, "lookup", detail or f"Searched: {target}", page, ua)

    async def _routine_share(self, persona, username, target, detail, _eb):
        """Access a file share that exists in this snapshot."""
        share = target or (random.choice(self._shares) if self._shares else "general")
        safe_share = shlex.quote(f"/srv/shares/{share}/")
        await self.containers.exec(
            self._host_files,
            f"ls {safe_share} 2>/dev/null || true",
        )
        return _file_log(persona, detail or f"Browsed {share} share", share)

    async def _routine_login(self, persona, username, target, detail, _eb):
        """Log into the web portal.

        Executes from the persona's source container, targeting the web
        server by hostname across the Docker network.
        """
        login_pages = [p for p in self._pages if "login" in p or "index" in p]
        page = login_pages[0] if login_pages else "/"
        ua = _random_ua()
        safe_ua = shlex.quote(ua)
        safe_data = shlex.quote(f"username={username}&password=placeholder")
        safe_url = shlex.quote(f"http://{self._host_web}{page}")
        source = self.source_for(persona)
        await self.containers.exec(
            source,
            f"curl -s -o /dev/null -A {safe_ua} -d {safe_data} {safe_url}",
        )
        return _auth_log(persona, detail or "Portal login", username, "success")

    async def _routine_query_db(self, persona, username, target, detail, _eb):
        """Query the database -- uses tables that exist in this snapshot.

        Runs on the DB host directly (mysql client lives there, not on
        the NPC workstation).  The query still appears in DB logs for
        Blue to observe.
        """
        import random

        if self._db_tables:
            table = random.choice(self._db_tables)
            query = f"SELECT * FROM {table} LIMIT 5"
        else:
            query = "SHOW TABLES"
        db_user, db_pass = self._db_creds
        safe_user = shlex.quote(db_user)
        safe_query = shlex.quote(query)
        if db_pass:
            safe_pass = shlex.quote(db_pass)
            cred_flag = f"-u {safe_user} -p{safe_pass}"
        else:
            cred_flag = f"-u {safe_user}"
        await self.containers.exec(
            self._host_db,
            f"mysql {cred_flag} -e {safe_query} 2>/dev/null || true",
        )
        return _db_log(persona, detail or f"Queried {target or 'database'}", query)

    async def _routine_idle(self, persona, username, target, detail, _eb):
        return _log(
            persona,
            "idle",
            detail or "Away from desk",
            "none",
            log_type="system_activity",
        )

    # ------------------------------------------------------------------
    # Reactive actions (response to stimuli from Red)
    # ------------------------------------------------------------------

    async def execute(self, persona: NPCPersona, action: NPCAction) -> dict[str, Any]:
        """Execute a reactive NPC action (response to stimulus)."""
        handler = {
            "click_link": self._react_click,
            "open_attachment": self._react_click,
            "reply": self._react_email,
            "forward": self._react_email,
            "share_credentials": self._react_share_creds,
            "report_to_IT": self._react_report,
            "ignore": self._react_ignore,
        }.get(action.action, self._react_ignore)
        return await handler(persona, action)

    async def _react_click(
        self, persona: NPCPersona, action: NPCAction
    ) -> dict[str, Any]:
        """Click a link from a stimulus.

        Executes from the persona's source container so the request crosses
        the Docker network and is visible to Blue on the wire.
        """
        url = f"http://{self._host_web}/"
        for effect in action.side_effects:
            urls = re.findall(r"https?://\S+", effect)
            if urls:
                url = urls[0].rstrip(".")
                break
        username = _username_from_persona(persona)
        safe_ua = shlex.quote(f"Mozilla/5.0 ({username})")
        safe_url = shlex.quote(url)
        source = self.source_for(persona)
        await self.containers.exec(
            source,
            f"curl -s -o /dev/null -A {safe_ua} {safe_url}",
        )
        return _se_log(
            persona, "click_link", f"Clicked: {url}", "web:access_log", result="success"
        )

    async def _react_email(
        self, persona: NPCPersona, action: NPCAction
    ) -> dict[str, Any]:
        username = _username_from_persona(persona)
        ts_i = int(time.time())
        body = (action.response_content or "acknowledged")[:500]
        safe_user = shlex.quote(username)
        safe_msg = shlex.quote(
            f"From: {username}@{self._domain}\\nSubject: Re\\n\\n{body}"
        )
        await self.containers.exec(
            self._host_mail,
            f"mkdir -p /var/mail/{safe_user} "
            f"&& echo {safe_msg} "
            f"> /var/mail/{safe_user}/sent_{ts_i}.eml",
        )
        return _se_log(
            persona, action.action, "Replied to message", "mail:spool", result="success"
        )

    async def _react_share_creds(
        self, persona: NPCPersona, action: NPCAction
    ) -> dict[str, Any]:
        """NPC shares credentials after social engineering.

        The curl login attempt executes from the persona's source container
        (crosses the network).  The SIEM alert is written locally inside
        the siem container.
        """
        username = _username_from_persona(persona)
        content = action.response_content or f"username: {username}"
        ts_i = int(time.time())
        source = self.source_for(persona)
        # Leaked creds file -- written on the source (persona's workstation)
        safe_content = shlex.quote(content)
        await self.containers.exec(
            source, f"echo {safe_content} >> /tmp/leaked_{ts_i}.txt"
        )
        # Suspicious login -- curl FROM source to web server by hostname
        safe_data = shlex.quote(f"username={username}&password=leaked")
        await self.containers.exec(
            source,
            f"curl -s -o /dev/null -A {shlex.quote('Mozilla/5.0 (external)')} "
            f"-d {safe_data} {shlex.quote(f'http://{self._host_web}/')}",
        )
        # SIEM alert -- written locally inside the siem container
        safe_name = shlex.quote(persona.id)
        await self.containers.exec(
            self._host_siem,
            f"printf '[%s] CRED-LEAK: %s shared credentials\\n' \"$(date)\" {safe_name} "
            f">> /var/log/siem/consolidated/all.log",
        )
        return _se_log(
            persona,
            "share_credentials",
            f"{persona.id} leaked credentials",
            "web+siem",
            result="success",
        )

    async def _react_report(
        self, persona: NPCPersona, action: NPCAction
    ) -> dict[str, Any]:
        detail = (
            "; ".join(action.side_effects)
            if action.side_effects
            else "suspicious activity"
        )
        safe_name = shlex.quote(persona.id)
        safe_detail = shlex.quote(detail)
        await self.containers.exec(
            self._host_siem,
            f"printf '[%s] NPC-REPORT: %s: %s\\n' \"$(date)\" {safe_name} {safe_detail} "
            f">> /var/log/siem/consolidated/all.log",
        )
        return _se_log(persona, "report_to_IT", detail, "siem:alert", result="blocked")

    async def _react_ignore(
        self, persona: NPCPersona, action: NPCAction
    ) -> dict[str, Any]:
        return _se_log(persona, "ignore", "Ignored stimulus", "none", result="blocked")


# ---------------------------------------------------------------------------
# Snapshot introspection -- derive available targets from the generated env
# ---------------------------------------------------------------------------


def _extract_web_pages(snapshot: SnapshotSpec) -> list[str]:
    """Extract URL paths from snapshot files dict (web:*.php -> /path).

    Handles arbitrary doc roots by stripping any ``/var/www/<app>/`` prefix
    to produce URL paths.
    """
    pages: list[str] = []
    for key in snapshot.files:
        if not key.startswith("web:"):
            continue
        path = key.split(":", 1)[1]
        if not path.endswith((".php", ".html", ".htm")):
            continue
        # Strip doc root: /var/www/<anything>/ -> /
        url_path = re.sub(r"^/var/www/[^/]+", "", path)
        if url_path:
            pages.append(url_path)
    return pages or ["/"]


def _extract_shares(snapshot: SnapshotSpec) -> list[str]:
    """Extract Samba share names from snapshot files dict."""
    shares: set[str] = set()
    for key in snapshot.files:
        if not key.startswith("files:"):
            continue
        path = key.split(":", 1)[1]
        # /srv/shares/<share_name>/file.txt -> share_name
        if "/srv/shares/" in path:
            parts = path.split("/srv/shares/")[1].split("/")
            if parts:
                shares.add(parts[0])
    return list(shares) or ["general"]


def _extract_db_tables(snapshot: SnapshotSpec) -> list[str]:
    """Extract table names from SQL in the snapshot files dict."""
    tables: set[str] = set()
    for key, content in snapshot.files.items():
        if key != "db:sql":
            continue
        # Find table names from INSERT INTO / SELECT FROM statements
        for match in re.finditer(
            r"(?:INSERT INTO|FROM|UPDATE)\s+(\w+\.?\w*)", content, re.IGNORECASE
        ):
            table = match.group(1)
            # Skip system tables
            if table.lower() not in (
                "information_schema",
                "mysql",
                "performance_schema",
            ):
                tables.add(table)
    return list(tables) or []


def _extract_users(snapshot: SnapshotSpec) -> list[str]:
    """Extract usernames from topology."""
    users = snapshot.topology.get("users", [])
    return [u["username"] for u in users if isinstance(u, dict) and "username" in u]


def _extract_db_credentials(snapshot: SnapshotSpec) -> tuple[str, str]:
    """Extract DB credentials from topology users. Fallback to defaults."""
    users = snapshot.topology.get("users", [])
    for user in users:
        if not isinstance(user, dict):
            continue
        hosts = user.get("hosts", [])
        if isinstance(hosts, list) and "db" in hosts:
            return (
                str(user.get("username", "app_user")),
                str(user.get("password") or "AppUs3r!2024"),
            )
    return "app_user", "AppUs3r!2024"


def _extract_ssh_credentials(snapshot: SnapshotSpec) -> tuple[str, str]:
    """Extract SSH admin credentials from topology users. Fallback to defaults."""
    users = snapshot.topology.get("users", [])
    for user in users:
        if not isinstance(user, dict):
            continue
        groups = user.get("groups", [])
        role = str(user.get("role", "")).strip().lower()
        if role in {"admin", "sysadmin", "root"} or (
            isinstance(groups, list) and "admins" in groups
        ):
            return (
                str(user.get("username", "admin")),
                str(user.get("password") or "Adm1n!2024"),
            )
    for user in users:
        if not isinstance(user, dict):
            continue
        hosts = user.get("hosts", [])
        if isinstance(hosts, list) and any(
            h in hosts for h in ("web", "files", "ldap", "siem")
        ):
            return (
                str(user.get("username", "admin")),
                str(user.get("password") or "Adm1n!2024"),
            )
    return "admin", "Adm1n!2024"


def _username_from_persona(persona: NPCPersona) -> str:
    email = persona.mailbox
    if "@" in email:
        return email.split("@")[0]
    return persona.id.lower().split()[0]


def _log(
    persona: NPCPersona,
    action: str,
    detail: str,
    source: str,
    *,
    log_type: str | None = None,
) -> dict[str, Any]:
    """Log a routine (benign) NPC action with a realistic event type."""
    return {
        "timestamp": time.time(),
        "type": log_type or f"npc_{action}",
        "label": "benign",
        "persona": persona.id,
        "department": persona.department,
        "action": action,
        "detail": detail,
        "source": source,
    }


def _web_log(
    persona: NPCPersona,
    action: str,
    detail: str,
    path: str,
    user_agent: str,
) -> dict[str, Any]:
    """Web-request log with realistic HTTP metadata (DoD #5)."""
    return {
        "timestamp": time.time(),
        "type": "web_request",
        "label": "benign",
        "persona": persona.id,
        "department": persona.department,
        "action": action,
        "detail": detail,
        "path": path,
        "user_agent": user_agent,
        "status_code": _random_status(),
        "bytes": _random_bytes(),
    }


def _chat_log(
    persona: NPCPersona,
    recipient: str,
    detail: str,
    source: str,
) -> dict[str, Any]:
    """NPC-to-NPC email/chat log (DoD #4)."""
    return {
        "timestamp": time.time(),
        "type": "npc_chat",
        "label": "benign",
        "persona": persona.id,
        "department": persona.department,
        "action": "send_email",
        "detail": detail,
        "recipient": recipient,
        "source": source,
    }


def _auth_log(
    persona: NPCPersona,
    detail: str,
    username: str,
    outcome: str,
) -> dict[str, Any]:
    """Authentication log with realistic fields (DoD #5)."""
    return {
        "timestamp": time.time(),
        "type": "auth",
        "label": "benign",
        "persona": persona.id,
        "department": persona.department,
        "action": "login",
        "detail": detail,
        "username": username,
        "outcome": outcome,
    }


def _file_log(
    persona: NPCPersona,
    detail: str,
    share: str,
) -> dict[str, Any]:
    """File-access log (DoD #5)."""
    return {
        "timestamp": time.time(),
        "type": "file_access",
        "label": "benign",
        "persona": persona.id,
        "department": persona.department,
        "action": "access_share",
        "detail": detail,
        "share": share,
    }


def _db_log(
    persona: NPCPersona,
    detail: str,
    query: str,
) -> dict[str, Any]:
    """Database-query log (DoD #5)."""
    return {
        "timestamp": time.time(),
        "type": "db_query",
        "label": "benign",
        "persona": persona.id,
        "department": persona.department,
        "action": "query_db",
        "detail": detail,
        "query": query,
    }


def _se_log(
    persona: NPCPersona,
    action: str,
    detail: str,
    source: str,
    *,
    result: str = "unknown",
) -> dict[str, Any]:
    """Log a social-engineering reactive NPC action for reward coupling."""
    return {
        "timestamp": time.time(),
        "type": "social_engineering",
        "label": "reactive",
        "persona": persona.id,
        "department": persona.department,
        "action": action,
        "detail": detail,
        "source": source,
        "result": result,
    }
