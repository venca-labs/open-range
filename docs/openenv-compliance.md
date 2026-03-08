# OpenEnv Compliance Guide

OpenRange implements the OpenEnv 0.2.x environment contract. This doc maps every requirement.

## Checklist

| Requirement | Status | Implementation |
|-------------|--------|----------------|
| `Environment` subclass | Done | `RangeEnvironment` extends `Environment[RangeAction, RangeObservation, RangeState]` when openenv is installed; falls back to plain `object` base with the same API surface |
| `reset()` returns `ObsT` | Done | Returns `RangeObservation` with episode briefing |
| `step()` returns `ObsT` | Done | Returns `RangeObservation` with stdout/stderr/reward/done |
| `state` property returns `StateT` | Done | Returns `RangeState` (episode_id, step_count, mode, flags_found, services_status, tier) |
| `Action` subclass (Pydantic, extra=forbid) | Done | `RangeAction(Action)` with `command: str`, `mode: Literal["red", "blue"]`. Note: `extra="forbid"` comes from the openenv `Action` base; the fallback stub inherits plain `BaseModel` without it |
| `Observation` subclass (Pydantic, extra=forbid) | Done | `RangeObservation(Observation)` — inherits `done`, `reward` from base; adds `stdout`, `stderr`, `flags_captured`, `alerts` |
| `State` subclass (Pydantic, extra=allow) | Done | `RangeState(State)` — inherits `episode_id`, `step_count` from base; adds `mode`, `flags_found`, `services_status`, `tier` |
| `create_app(Class, ActionType, ObsType)` | Done | `app.py` tries `openenv.core.env_server.create_app(RangeEnvironment, RangeAction, RangeObservation, env_name="open_range")`; falls back to a standalone FastAPI app with equivalent endpoints |
| `EnvClient` subclass | Done | `OpenRangeEnv(EnvClient[RangeAction, RangeObservation, RangeState])` when openenv is installed; stub client otherwise |
| `_step_payload()` | Done | Returns `{"command": action.command, "mode": action.mode}` |
| `_parse_result()` | Done | Parses server response to `StepResult[RangeObservation]` |
| `_parse_state()` | Done | Parses server response to `RangeState` |
| `/health` endpoint | Done | Returns `{"status": "ok"}` (standalone) or openenv default |
| `/metadata` endpoint | Done | Returns name, version, description, supports_concurrent_sessions |
| `/schema` endpoint | Done | Returns JSON schemas for RangeAction, RangeObservation, RangeState |
| `/ws` WebSocket | Done | Standalone implementation with per-connection `RangeEnvironment` instance; accepts `reset`, `step`, `state` message types |
| `/reset`, `/step`, `/state` HTTP | Done | POST /reset, POST /step, GET /state — all implemented in standalone fallback and via `create_app` |
| `Rubric` for rewards | Done | `CompositeRedReward`, `CompositeBlueReward` (lazy-loaded in `RangeEnvironment._apply_rewards`) |
| `openenv.yaml` manifest | Done | `openenv.yaml` at project root (name: open_range, version: 0.1.0) |
| `Dockerfile` | Done | `server/Dockerfile` — Python 3.11-slim, docker.io + curl, healthcheck on `/health`, CMD uvicorn |
| `python -m open_range.server` entry point | Done | `server/__main__.py` — starts uvicorn with `--host`, `--port`, `--reload`, `--log-level` flags |

## Dual-Mode Server

The server (`app.py`) operates in two modes:

1. **OpenEnv mode** — when `openenv` is installed, delegates to `openenv.core.env_server.create_app` which provides all endpoints automatically.
2. **Standalone mode** — when `openenv` is not installed, runs a self-contained FastAPI app with equivalent HTTP endpoints (GET /health, GET /metadata, GET /schema, POST /reset, POST /step, GET /state) and a WebSocket endpoint at `/ws` with per-connection environment isolation.

Both modes serve the same contract. The standalone fallback ensures the server works without the openenv package installed.

### WebSocket Protocol

The `/ws` endpoint accepts JSON messages with a `type` field:

- `{"type": "reset"}` or `{"type": "reset", "seed": 42, "episode_id": "ep1"}` — reset the environment
- `{"type": "step", "command": "nmap -sV 10.0.1.2", "mode": "red"}` — execute an action
- `{"type": "state"}` — get current episode state

Responses include a `type` field: `"observation"`, `"state"`, or `"error"`.

## Deployment

The OpenEnv server runs as a **container in the same Docker Compose stack** as the enterprise range. It reaches range containers via the Docker SDK (mounted `/var/run/docker.sock`).

```mermaid
flowchart TD
    subgraph compose [docker-compose.yml]
        subgraph server [OpenEnv Server Container]
            APP[FastAPI app<br/>/health, /metadata, /schema,<br/>/reset, /step, /state, /ws]
        end
        subgraph range [Enterprise Range - 8 containers]
            ATK[attacker] --- FW[firewall]
            FW --- WEB[web] --- MAIL[mail]
            WEB --- DB[db] --- FILES[files]
            DB --- LDAP[ldap] --- SIEM[siem]
        end
        SOCK[docker.sock mount]
    end

    APP -->|docker SDK| SOCK
    SOCK -->|docker exec| range
    APP -->|port 8000| EXT[External clients]

    style server fill:#6bcb7722,stroke:#6bcb77
    style range fill:#7c73e622,stroke:#7c73e6
```

`reset()` selects a pre-validated frozen snapshot from the snapshot store. No LLM calls in the hot path -- snapshot generation is asynchronous.

## Common Mistakes to Avoid

1. **Don't redeclare `done` or `reward` on Observation.** The base class already has them. `RangeObservation` correctly inherits them.
2. **Don't redeclare `episode_id` or `step_count` on State.** The base class already has them. `RangeState` correctly inherits them.
3. **Pass the CLASS to `create_app()`, not an instance.** Each WebSocket session gets its own instance. The standalone fallback also creates per-session instances for WebSocket.
4. **Action uses `extra="forbid"` (via openenv base).** Unknown fields cause validation errors. Keep actions minimal. Note: the fallback `Action` stub does not enforce `extra="forbid"`.
5. **State uses `extra="allow"`.** You can add any fields you want.
6. **`reset()` returns ObsT (server-side), `StepResult[ObsT]` (client-side).** The server wraps it.
7. **All openenv imports are guarded with try/except.** Models, environment, client, and app all fall back gracefully when openenv is not installed.

## API Signatures (Exact)

```python
# Server-side (src/open_range/server/environment.py)
class RangeEnvironment(Environment[RangeAction, RangeObservation, RangeState]):
    # Falls back to object base when openenv is not installed
    SUPPORTS_CONCURRENT_SESSIONS = False

    def __init__(self, max_steps: int = 100, exec_timeout: float = 30.0,
                 docker_available: bool | None = None) -> None: ...
    def reset(self, seed: int | None = None,
              episode_id: str | None = None, **kwargs) -> RangeObservation: ...
    def step(self, action: RangeAction,
             timeout_s: float | None = None, **kwargs) -> RangeObservation: ...
    @property
    def state(self) -> RangeState: ...

# Client-side (src/open_range/client/client.py)
class OpenRangeEnv(EnvClient[RangeAction, RangeObservation, RangeState]):
    # Falls back to a stub class when openenv is not installed
    def _step_payload(self, action: RangeAction) -> dict: ...
    def _parse_result(self, payload: dict) -> StepResult[RangeObservation]: ...
    def _parse_state(self, payload: dict) -> RangeState: ...

# App factory (src/open_range/server/app.py)
# Tries openenv's create_app first:
app = create_app(RangeEnvironment, RangeAction, RangeObservation, env_name="open_range")
# Falls back to standalone FastAPI app with equivalent HTTP + WebSocket endpoints

# Entry point (src/open_range/server/__main__.py)
# python -m open_range.server [--host HOST] [--port PORT] [--reload] [--log-level LEVEL]
```

## Reference Implementations

Study these OpenEnv environments as patterns:

- **`envs/coding_env/`** — closest analog (execute code, get stdout/stderr). Uses `Environment` base.
- **`envs/echo_env/`** — simplest possible environment. Uses `MCPEnvironment` base.
- **`envs/finqa_env/`** — MCP tool-based with complex rewards. Uses `MCPEnvironment` base.
