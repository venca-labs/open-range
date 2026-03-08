"""Operator debugging console for OpenRange.

Provides a lightweight HTML-based single-page application for monitoring
the range environment state, viewing action history, and triggering resets.
"""

from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse

console_router = APIRouter(prefix="/console", tags=["console"])

# ---------------------------------------------------------------------------
# In-memory action history (shared across the module)
# ---------------------------------------------------------------------------

_action_history: list[dict[str, Any]] = []
_MAX_HISTORY = 50  # keep more than 20 internally, but serve 20


def record_action(action_record: dict[str, Any]) -> None:
    """Append an action record to the console history ring buffer."""
    _action_history.append(action_record)
    if len(_action_history) > _MAX_HISTORY:
        del _action_history[: len(_action_history) - _MAX_HISTORY]


def clear_history() -> None:
    """Clear the action history (called on reset)."""
    _action_history.clear()


def get_history(limit: int = 20) -> list[dict[str, Any]]:
    """Return the most recent *limit* action records, newest first."""
    return list(reversed(_action_history[-limit:]))


# ---------------------------------------------------------------------------
# API routes
# ---------------------------------------------------------------------------


@console_router.get("/api/snapshot")
async def api_snapshot(request: Request) -> JSONResponse:
    """Return current snapshot metadata (no truth graph or flags)."""
    ctx = _get_env_context(request)
    env = ctx["env"]
    snapshot = env.snapshot
    if snapshot is None:
        return JSONResponse({
            "id": None,
            "tier": None,
            "hosts": [],
            "zones": {},
            "vuln_count": 0,
            "state_scope": ctx["state_scope"],
            "session_id": ctx["session_id"],
            "warning": ctx["warning"],
        })

    topo = snapshot.topology if isinstance(snapshot.topology, dict) else {}
    hosts = topo.get("hosts", [])
    zones = topo.get("zones", {})
    tier = topo.get("tier", 1)
    vuln_count = len(snapshot.truth_graph.vulns) if snapshot.truth_graph else 0

    return JSONResponse({
        "id": env.state.episode_id,
        "tier": tier,
        "hosts": hosts,
        "zones": zones,
        "vuln_count": vuln_count,
        "state_scope": ctx["state_scope"],
        "session_id": ctx["session_id"],
        "warning": ctx["warning"],
    })


@console_router.get("/api/episode")
async def api_episode(request: Request) -> JSONResponse:
    """Return current episode state."""
    ctx = _get_env_context(request)
    env = ctx["env"]
    state = env.state
    return JSONResponse({
        "step_count": state.step_count,
        "flags_found": len(state.flags_found),
        "mode": state.mode,
        "services_status": state.services_status,
        "state_scope": ctx["state_scope"],
        "session_id": ctx["session_id"],
        "warning": ctx["warning"],
    })


@console_router.get("/api/history")
async def api_history() -> JSONResponse:
    """Return recent action history (last 20 actions with timestamps)."""
    return JSONResponse(get_history(20))


@console_router.get("", response_class=HTMLResponse)
@console_router.get("/", response_class=HTMLResponse)
async def console_page() -> HTMLResponse:
    """Serve the single-page operator console."""
    return HTMLResponse(_CONSOLE_HTML)


# ---------------------------------------------------------------------------
# Helper to retrieve the environment from app state
# ---------------------------------------------------------------------------


def _get_env_context(request: Request) -> dict[str, Any]:
    """Resolve the environment context used by the console endpoints.

    Priority:
    1. Active OpenEnv WebSocket session environment (session-scoped truth)
    2. ``app.state.env`` fallback environment (global app scope)
    3. Lazily created fallback environment (tests/dev)
    """
    app = request.app

    server = getattr(app.state, "openenv_server", None)
    sessions = getattr(server, "_sessions", None)
    if isinstance(sessions, dict) and sessions:
        if len(sessions) == 1:
            session_id, env = next(iter(sessions.items()))
            return {
                "env": env,
                "state_scope": "websocket_session",
                "session_id": session_id,
                "warning": None,
            }

        session_info = getattr(server, "_session_info", {})
        selected_id = max(
            sessions.keys(),
            key=lambda sid: float(getattr(session_info.get(sid), "last_activity_at", 0.0) or 0.0),
        )
        return {
            "env": sessions[selected_id],
            "state_scope": "websocket_session",
            "session_id": selected_id,
            "warning": (
                f"{len(sessions)} active sessions detected; "
                f"showing the most recently active session ({selected_id})."
            ),
        }

    if hasattr(app.state, "env"):
        return {
            "env": app.state.env,
            "state_scope": "app_state_env",
            "session_id": None,
            "warning": (
                "No active WebSocket session found; console is showing shared "
                "app-state environment data."
            ),
        }

    # Fallback: create an ephemeral environment (tests/dev)
    from open_range.server.environment import RangeEnvironment

    if not hasattr(app.state, "_fallback_env"):
        app.state._fallback_env = RangeEnvironment(docker_available=False)
    return {
        "env": app.state._fallback_env,
        "state_scope": "fallback_env",
        "session_id": None,
        "warning": "Console is using a fallback environment (no server session available).",
    }


def _get_env(request: Request) -> Any:
    """Compatibility helper for callers that only need the env object."""
    return _get_env_context(request)["env"]


# ---------------------------------------------------------------------------
# HTML template (inline JS, no build step)
# ---------------------------------------------------------------------------

_CONSOLE_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OpenRange Operator Console</title>
<style>
  :root {
    --bg: #0d1117;
    --surface: #161b22;
    --border: #30363d;
    --text: #c9d1d9;
    --text-dim: #8b949e;
    --accent: #58a6ff;
    --green: #3fb950;
    --red: #f85149;
    --yellow: #d29922;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: "SF Mono", "Fira Code", "Cascadia Code", Consolas, monospace;
    font-size: 14px;
    line-height: 1.5;
    padding: 24px;
  }
  h1 {
    font-size: 20px;
    color: var(--accent);
    margin-bottom: 4px;
  }
  .subtitle {
    color: var(--text-dim);
    font-size: 12px;
    margin-bottom: 20px;
  }
  .grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 16px;
    margin-bottom: 16px;
  }
  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 16px;
  }
  .card-title {
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--text-dim);
    margin-bottom: 12px;
  }
  .field { margin-bottom: 8px; }
  .field-label {
    display: inline-block;
    width: 120px;
    color: var(--text-dim);
  }
  .field-value {
    color: var(--text);
  }
  .tag {
    display: inline-block;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 3px;
    padding: 1px 6px;
    font-size: 12px;
    margin: 2px;
  }
  .history-card {
    grid-column: 1 / -1;
  }
  .history-list {
    max-height: 400px;
    overflow-y: auto;
    border: 1px solid var(--border);
    border-radius: 4px;
  }
  .history-item {
    padding: 8px 12px;
    border-bottom: 1px solid var(--border);
    font-size: 13px;
  }
  .history-item:last-child { border-bottom: none; }
  .history-item .step {
    color: var(--text-dim);
    font-size: 11px;
  }
  .history-item .cmd {
    color: var(--green);
  }
  .history-item .mode-red { color: var(--red); }
  .history-item .mode-blue { color: var(--accent); }
  .history-item .ts {
    color: var(--text-dim);
    font-size: 11px;
    float: right;
  }
  .empty-state {
    color: var(--text-dim);
    padding: 24px;
    text-align: center;
  }
  .actions-bar {
    margin-bottom: 16px;
  }
  button {
    background: var(--surface);
    color: var(--accent);
    border: 1px solid var(--accent);
    border-radius: 4px;
    padding: 6px 16px;
    font-family: inherit;
    font-size: 13px;
    cursor: pointer;
    transition: background 0.15s;
  }
  button:hover {
    background: var(--accent);
    color: var(--bg);
  }
  button:disabled {
    opacity: 0.4;
    cursor: not-allowed;
  }
  .status-dot {
    display: inline-block;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    margin-right: 6px;
  }
  .status-dot.active { background: var(--green); }
  .status-dot.idle { background: var(--yellow); }
</style>
</head>
<body>

<h1>OpenRange Operator Console</h1>
<p class="subtitle">Debugging dashboard &mdash; auto-refreshes every 2s</p>

<div class="actions-bar">
  <button id="btn-reset" onclick="doReset()">Reset Environment</button>
  <button id="btn-refresh" onclick="refresh()">Refresh Now</button>
</div>

<div class="grid">
  <!-- Snapshot card -->
  <div class="card" id="snapshot-card">
    <div class="card-title">Snapshot</div>
    <div id="snapshot-content">
      <div class="empty-state">No snapshot loaded</div>
    </div>
  </div>

  <!-- Episode card -->
  <div class="card" id="episode-card">
    <div class="card-title">Episode State</div>
    <div id="episode-content">
      <div class="empty-state">Waiting for data...</div>
    </div>
  </div>

  <!-- History card -->
  <div class="card history-card">
    <div class="card-title">Action History (last 20)</div>
    <div class="history-list" id="history-list">
      <div class="empty-state">No actions recorded</div>
    </div>
  </div>
</div>

<script>
const BASE = window.location.origin;

function esc(s) {
  const d = document.createElement("div");
  d.textContent = s;
  return d.innerHTML;
}

function fmtTime(ts) {
  if (!ts) return "";
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString();
}

async function fetchJSON(path) {
  try {
    const r = await fetch(BASE + path);
    if (!r.ok) return null;
    return await r.json();
  } catch(e) { return null; }
}

function renderSnapshot(data) {
  const el = document.getElementById("snapshot-content");
  if (!data || !data.id) {
    el.innerHTML = '<div class="empty-state">No snapshot loaded</div>';
    return;
  }
  const hosts = (data.hosts || []).map(h => '<span class="tag">' + esc(h) + '</span>').join(" ");
  const zones = Object.keys(data.zones || {}).map(z => '<span class="tag">' + esc(z) + '</span>').join(" ");
  el.innerHTML =
    '<div class="field"><span class="field-label">Episode ID</span><span class="field-value">' + esc(data.id) + '</span></div>' +
    '<div class="field"><span class="field-label">Tier</span><span class="field-value">' + (data.tier || "-") + '</span></div>' +
    '<div class="field"><span class="field-label">Hosts</span><span class="field-value">' + (hosts || "-") + '</span></div>' +
    '<div class="field"><span class="field-label">Zones</span><span class="field-value">' + (zones || "-") + '</span></div>' +
    '<div class="field"><span class="field-label">Vuln Count</span><span class="field-value">' + (data.vuln_count || 0) + '</span></div>';
}

function renderEpisode(data) {
  const el = document.getElementById("episode-content");
  if (!data) {
    el.innerHTML = '<div class="empty-state">Waiting for data...</div>';
    return;
  }
  const active = data.step_count > 0;
  const dotClass = active ? "active" : "idle";
  el.innerHTML =
    '<div class="field"><span class="field-label">Status</span><span class="field-value"><span class="status-dot ' + dotClass + '"></span>' + (active ? "Active" : "Idle") + '</span></div>' +
    '<div class="field"><span class="field-label">Step Count</span><span class="field-value">' + data.step_count + '</span></div>' +
    '<div class="field"><span class="field-label">Flags Found</span><span class="field-value">' + data.flags_found + '</span></div>' +
    '<div class="field"><span class="field-label">Mode</span><span class="field-value">' + (data.mode || "-") + '</span></div>';
}

function renderHistory(items) {
  const el = document.getElementById("history-list");
  if (!items || items.length === 0) {
    el.innerHTML = '<div class="empty-state">No actions recorded</div>';
    return;
  }
  el.innerHTML = items.map(function(it) {
    const modeClass = it.mode === "red" ? "mode-red" : "mode-blue";
    return '<div class="history-item">' +
      '<span class="ts">' + fmtTime(it.time) + '</span>' +
      '<span class="step">step ' + (it.step || "-") + '</span> ' +
      '<span class="' + modeClass + '">[' + esc(it.mode || "?") + ']</span> ' +
      '<span class="cmd">' + esc(it.command || it.type || "") + '</span>' +
      '</div>';
  }).join("");
}

async function refresh() {
  const [snap, ep, hist] = await Promise.all([
    fetchJSON("/console/api/snapshot"),
    fetchJSON("/console/api/episode"),
    fetchJSON("/console/api/history"),
  ]);
  renderSnapshot(snap);
  renderEpisode(ep);
  renderHistory(hist);
}

async function doReset() {
  const btn = document.getElementById("btn-reset");
  btn.disabled = true;
  btn.textContent = "Resetting...";
  try {
    await fetch(BASE + "/reset", { method: "POST", headers: {"Content-Type": "application/json"}, body: "{}" });
    await refresh();
  } catch(e) {
    console.error("Reset failed:", e);
  }
  btn.disabled = false;
  btn.textContent = "Reset Environment";
}

// Initial load
refresh();

// Auto-refresh every 2 seconds
setInterval(refresh, 2000);
</script>

</body>
</html>
"""
