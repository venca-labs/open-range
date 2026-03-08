"""NPC action executor -- bridges NPC decisions to container state changes.

All actions are derived from the SnapshotSpec at init time, so they adapt
to whatever environment the Builder LLM generated.  No hardcoded pages,
tables, or endpoints.
"""

from __future__ import annotations

import logging
import re
import shlex
import time
from typing import Any

from open_range.protocols import ContainerSet, NPCAction, NPCPersona, SnapshotSpec

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
        # Derive available targets from the snapshot
        self._pages = _extract_web_pages(snapshot)
        self._shares = _extract_shares(snapshot)
        self._db_tables = _extract_db_tables(snapshot)
        self._users = _extract_users(snapshot)
        self._domain = snapshot.topology.get("domain", "corp.local")
        self._db_creds = _extract_db_credentials(snapshot)
        self._ssh_creds = _extract_ssh_credentials(snapshot)

        # Resolve logical roles to actual hostnames from the topology
        self._host_web = _resolve_host(snapshot, ["nginx", "apache", "httpd", "web", "php-fpm"], "web")
        self._host_mail = _resolve_host(snapshot, ["postfix", "sendmail", "dovecot", "mail"], "mail")
        self._host_db = _resolve_host(snapshot, ["mysql", "mariadb", "postgres", "mongodb"], "db")
        self._host_siem = _resolve_host(snapshot, ["rsyslog", "elasticsearch", "siem", "splunk"], "siem")
        self._host_files = _resolve_host(snapshot, ["samba", "smb", "files", "nfs"], "files")

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
        """Browse a page that exists in this snapshot."""
        path = target if target.startswith("/") else f"/{target}" if target else "/"
        # Fall back to a known page if target isn't in snapshot
        if path == "/" and self._pages:
            import random
            path = random.choice(self._pages)
        safe_path = shlex.quote(f"http://localhost{path}")
        safe_ua = shlex.quote(f"Mozilla/5.0 ({username})")
        await self.containers.exec(
            self._host_web,
            f"curl -s -o /dev/null -A {safe_ua} {safe_path}",
        )
        return _log(persona, "browse", detail or f"Browsed {path}", f"web:{path}")

    async def _routine_email(self, persona, username, target, detail, body):
        """Send email to a colleague (picks a real user from topology)."""
        import random
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
        safe_msg = shlex.quote(msg)
        await self.containers.exec(
            self._host_mail,
            f"mkdir -p /var/mail/{safe_user} "
            f"&& echo {safe_msg} > /var/mail/{safe_user}/sent_{ts_i}.eml",
        )
        return _log(persona, "send_email", detail or f"Emailed {recipient}", f"mail:{username}")

    async def _routine_lookup(self, persona, username, target, detail, _eb):
        """Look up data on the web app -- uses whatever search/lookup page exists."""
        # Find a page with query params in the snapshot
        lookup_pages = [p for p in self._pages if "?" in p or "lookup" in p or "search" in p]
        if lookup_pages:
            import random
            page = random.choice(lookup_pages)
        elif self._pages:
            import random
            page = random.choice(self._pages) + "?q=" + (target or "status")
        else:
            page = f"/?q={target or 'data'}"

        safe_url = shlex.quote(f"http://localhost{page}")
        safe_ua = shlex.quote(f"Mozilla/5.0 ({username})")
        await self.containers.exec(
            self._host_web,
            f"curl -s -o /dev/null -A {safe_ua} {safe_url}",
        )
        return _log(persona, "lookup", detail or f"Searched: {target}", f"web:{page}")

    async def _routine_share(self, persona, username, target, detail, _eb):
        """Access a file share that exists in this snapshot."""
        import random
        share = target or (random.choice(self._shares) if self._shares else "general")
        safe_share = shlex.quote(f"/srv/shares/{share}/")
        await self.containers.exec(
            self._host_files,
            f"ls {safe_share} 2>/dev/null || true",
        )
        return _log(persona, "access_share", detail or f"Browsed {share} share", f"files:{share}")

    async def _routine_login(self, persona, username, target, detail, _eb):
        """Log into the web portal."""
        # Find the login page from snapshot
        login_pages = [p for p in self._pages if "login" in p or "index" in p]
        page = login_pages[0] if login_pages else "/"
        safe_ua = shlex.quote(f"Mozilla/5.0 ({username})")
        safe_data = shlex.quote(f"username={username}&password=placeholder")
        safe_url = shlex.quote(f"http://localhost{page}")
        await self.containers.exec(
            self._host_web,
            f"curl -s -o /dev/null -A {safe_ua} -d {safe_data} {safe_url}",
        )
        return _log(persona, "login", detail or "Portal login", "web:access_log")

    async def _routine_query_db(self, persona, username, target, detail, _eb):
        """Query the database -- uses tables that exist in this snapshot."""
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
        return _log(persona, "query_db", detail or f"Queried {target or 'database'}", "db:query_log")

    async def _routine_idle(self, persona, username, target, detail, _eb):
        return _log(persona, "idle", detail or "Away from desk", "none")

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

    async def _react_click(self, persona: NPCPersona, action: NPCAction) -> dict[str, Any]:
        url = "http://localhost/"
        for effect in action.side_effects:
            urls = re.findall(r"https?://\S+", effect)
            if urls:
                url = urls[0].rstrip(".")
                break
        username = _username_from_persona(persona)
        safe_ua = shlex.quote(f"Mozilla/5.0 ({username})")
        safe_url = shlex.quote(url)
        await self.containers.exec(
            self._host_web,
            f"curl -s -o /dev/null -A {safe_ua} {safe_url}",
        )
        return _se_log(persona, "click_link", f"Clicked: {url}", "web:access_log", result="success")

    async def _react_email(self, persona: NPCPersona, action: NPCAction) -> dict[str, Any]:
        username = _username_from_persona(persona)
        ts_i = int(time.time())
        body = (action.response_content or "acknowledged")[:500]
        safe_user = shlex.quote(username)
        safe_msg = shlex.quote(f"From: {username}@{self._domain}\\nSubject: Re\\n\\n{body}")
        await self.containers.exec(
            self._host_mail,
            f"mkdir -p /var/mail/{safe_user} "
            f"&& echo {safe_msg} "
            f"> /var/mail/{safe_user}/sent_{ts_i}.eml",
        )
        return _se_log(persona, action.action, "Replied to message", "mail:spool", result="success")

    async def _react_share_creds(self, persona: NPCPersona, action: NPCAction) -> dict[str, Any]:
        username = _username_from_persona(persona)
        content = action.response_content or f"username: {username}"
        ts_i = int(time.time())
        # Leaked creds file
        safe_content = shlex.quote(content)
        await self.containers.exec(self._host_web, f"echo {safe_content} >> /tmp/leaked_{ts_i}.txt")
        # Suspicious login
        safe_data = shlex.quote(f"username={username}&password=leaked")
        await self.containers.exec(
            self._host_web,
            f"curl -s -o /dev/null -A {shlex.quote('Mozilla/5.0 (external)')} "
            f"-d {safe_data} {shlex.quote('http://localhost/')}",
        )
        # SIEM alert
        safe_name = shlex.quote(persona.name)
        await self.containers.exec(
            self._host_siem,
            f"printf '[%s] CRED-LEAK: %s shared credentials\\n' \"$(date)\" {safe_name} "
            f">> /var/log/siem/consolidated/all.log",
        )
        return _se_log(persona, "share_credentials", f"{persona.name} leaked credentials", "web+siem", result="success")

    async def _react_report(self, persona: NPCPersona, action: NPCAction) -> dict[str, Any]:
        detail = "; ".join(action.side_effects) if action.side_effects else "suspicious activity"
        safe_name = shlex.quote(persona.name)
        safe_detail = shlex.quote(detail)
        await self.containers.exec(
            self._host_siem,
            f"printf '[%s] NPC-REPORT: %s: %s\\n' \"$(date)\" {safe_name} {safe_detail} "
            f">> /var/log/siem/consolidated/all.log",
        )
        return _se_log(persona, "report_to_IT", detail, "siem:alert", result="blocked")

    async def _react_ignore(self, persona: NPCPersona, action: NPCAction) -> dict[str, Any]:
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
        for match in re.finditer(r"(?:INSERT INTO|FROM|UPDATE)\s+(\w+\.?\w*)", content, re.IGNORECASE):
            table = match.group(1)
            # Skip system tables
            if table.lower() not in ("information_schema", "mysql", "performance_schema"):
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
        if "db" in hosts:
            return user.get("username", "app_user"), user.get("password", "")
    return "app_user", "AppUs3r!2024"


def _extract_ssh_credentials(snapshot: SnapshotSpec) -> tuple[str, str]:
    """Extract SSH admin credentials from topology users. Fallback to defaults."""
    users = snapshot.topology.get("users", [])
    # First pass: look for explicit admin roles
    for user in users:
        if not isinstance(user, dict):
            continue
        role = user.get("role", "")
        if role in ("admin", "sysadmin", "root"):
            return user.get("username", "admin"), user.get("password", "")
    # Second pass: look for users on SSH-accessible hosts
    for user in users:
        if not isinstance(user, dict):
            continue
        hosts = user.get("hosts", [])
        if any(h in hosts for h in ("web", "files", "ldap", "siem")):
            return user.get("username", "admin"), user.get("password", "")
    return "admin", "Adm1n!2024"


def _username_from_persona(persona: NPCPersona) -> str:
    email = persona.accounts.get("email", "")
    if "@" in email:
        return email.split("@")[0]
    return persona.name.lower().split()[0]


def _log(persona: NPCPersona, action: str, detail: str, source: str) -> dict[str, Any]:
    """Log a routine (benign) NPC action."""
    return {
        "timestamp": time.time(),
        "type": f"npc_{action}",
        "label": "benign",
        "persona": persona.name,
        "department": persona.department,
        "action": action,
        "detail": detail,
        "source": source,
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
        "persona": persona.name,
        "department": persona.department,
        "action": action,
        "detail": detail,
        "source": source,
        "result": result,
    }
