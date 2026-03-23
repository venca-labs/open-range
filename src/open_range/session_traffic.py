"""Shell script templates for NPC traffic with session/token headers.

Generates shell script snippets that run inside NPC containers to
produce authenticated HTTP traffic (curl with Cookie and Authorization
headers), periodic token refresh loops, and session cleanup.

These scripts are deployed by the NPC manager alongside the existing
Level 0 traffic scripts.  They are completely optional -- when the
credential lifecycle is not enabled the NPC manager simply skips them.
"""

from __future__ import annotations

import shlex

from open_range.credential_lifecycle import (
    CredentialLifecycleConfig,
    NPCSession,
)


def generate_authenticated_http_traffic(
    session: NPCSession,
    target_url: str,
    actions: list[str],
) -> str:
    """Generate a shell script snippet for authenticated HTTP traffic.

    Uses curl with Cookie and Authorization headers from the session.
    Each action becomes a separate curl call so that Blue sees distinct
    log entries per request.

    Args:
        session: Active NPC session with tokens.
        target_url: Base URL to target (e.g. ``http://web``).
        actions: List of URL paths / endpoints to hit.

    Returns:
        A multi-line shell script string ready for ``sh -c`` execution.
    """
    lines: list[str] = [
        "#!/bin/sh",
        "# NPC authenticated traffic for " + shlex.quote(session.username),
        f"SESSION_ID={shlex.quote(session.session_id)}",
    ]

    if session.bearer_token is not None:
        lines.append(f"BEARER={shlex.quote(session.bearer_token)}")
        auth_flags = (
            '-H "Cookie: session=$SESSION_ID" -H "Authorization: Bearer $BEARER"'
        )
    else:
        auth_flags = '-H "Cookie: session=$SESSION_ID"'

    safe_ua = shlex.quote(f"Mozilla/5.0 (NPC/{session.username})")

    for action in actions:
        safe_url = shlex.quote(f"{target_url.rstrip('/')}/{action.lstrip('/')}")
        lines.append(f"curl -s -o /dev/null -A {safe_ua} {auth_flags} {safe_url}")

    return "\n".join(lines) + "\n"


def generate_token_refresh_script(
    config: CredentialLifecycleConfig,
    username: str,
) -> str:
    """Generate a shell script that periodically refreshes tokens.

    Runs as a background process in the NPC's container.  Reads the
    current session file, requests a fresh token from a local endpoint,
    and writes the updated token back to the session file.

    In practice the NPC manager calls ``CredentialLifecycleManager.refresh_token``
    in Python and re-deploys the session file.  This script is a
    self-contained fallback that simulates the refresh cycle purely in
    shell so that traffic patterns remain visible to Blue even when the
    Python manager is not actively driving the container.

    Args:
        config: Credential lifecycle configuration.
        username: NPC username whose tokens should be refreshed.

    Returns:
        A complete shell script string.
    """
    session_file = f"/tmp/sessions/{shlex.quote(username)}.json"
    refresh_interval = (
        config.token_ttl_minutes * 60 - config.token_refresh_margin_seconds
    )
    # Ensure a sane minimum interval
    if refresh_interval < 30:
        refresh_interval = 30

    script = f"""\
#!/bin/sh
# Token refresh loop for NPC {shlex.quote(username)}
# Refreshes every {refresh_interval}s (TTL {config.token_ttl_minutes}m - margin {config.token_refresh_margin_seconds}s)

SESSION_FILE="{session_file}"
REFRESH_INTERVAL={refresh_interval}

mkdir -p /tmp/sessions

while true; do
    sleep "$REFRESH_INTERVAL"

    if [ ! -f "$SESSION_FILE" ]; then
        echo "[$(date -Iseconds)] session file missing for {shlex.quote(username)}, skipping refresh" >&2
        continue
    fi

    # Read current session data
    OLD_JTI=$(cat "$SESSION_FILE" | grep -o '"token_jti": *"[^"]*"' | head -1 | cut -d'"' -f4)
    TIMESTAMP=$(date +%s)

    # Generate a new pseudo-random JTI (best-effort without Python)
    NEW_JTI=$(head -c 16 /dev/urandom 2>/dev/null | od -An -tx1 | tr -d ' \\n' | head -c 22)

    # Update the session file with new refresh timestamp and JTI
    if command -v jq >/dev/null 2>&1; then
        jq --arg jti "$NEW_JTI" --argjson ts "$TIMESTAMP" \\
            '.token_jti = $jti | .last_refresh_at = $ts' \\
            "$SESSION_FILE" > "$SESSION_FILE.tmp" && mv "$SESSION_FILE.tmp" "$SESSION_FILE"
    else
        # Fallback: sed-based rewrite (less robust but works without jq)
        sed -i "s/\\"token_jti\\": *\\"[^\\"]*\\"/\\"token_jti\\": \\"$NEW_JTI\\"/" "$SESSION_FILE" 2>/dev/null
        sed -i "s/\\"last_refresh_at\\": *[0-9.]*/\\"last_refresh_at\\": $TIMESTAMP/" "$SESSION_FILE" 2>/dev/null
    fi

    echo "[$(date -Iseconds)] refreshed token for {shlex.quote(username)} (jti: $OLD_JTI -> $NEW_JTI)"
done
"""
    return script


def generate_session_cleanup_script() -> str:
    """Generate a script that cleans up expired session files.

    Designed to run periodically (e.g. via cron or a background loop)
    to remove stale session files from ``/tmp/sessions/``.

    Returns:
        A complete shell script string.
    """
    script = """\
#!/bin/sh
# Clean up expired NPC session files from /tmp/sessions/
# Run periodically to remove stale sessions.

SESSION_DIR="/tmp/sessions"

if [ ! -d "$SESSION_DIR" ]; then
    exit 0
fi

NOW=$(date +%s)

for f in "$SESSION_DIR"/*.json; do
    [ -f "$f" ] || continue

    # Extract session_expires_at from the JSON file
    if command -v jq >/dev/null 2>&1; then
        EXPIRES=$(jq -r '.session_expires_at // 0' "$f" 2>/dev/null)
    else
        EXPIRES=$(grep -o '"session_expires_at": *[0-9.]*' "$f" | head -1 | grep -o '[0-9.]*$')
    fi

    # Default to 0 if extraction failed
    EXPIRES=${EXPIRES:-0}
    # Truncate to integer for shell comparison
    EXPIRES_INT=${EXPIRES%%.*}

    if [ "$EXPIRES_INT" -gt 0 ] && [ "$EXPIRES_INT" -lt "$NOW" ]; then
        USERNAME=$(basename "$f" .json)
        echo "[$(date -Iseconds)] removing expired session for $USERNAME (expired at $EXPIRES)"
        rm -f "$f"
    fi
done
"""
    return script
