# OpenEnv Compliance Guide

OpenRange implements the OpenEnv 0.2.x environment contract. This doc maps every requirement.

## Checklist

| Requirement | Status | Implementation |
|-------------|--------|----------------|
| `Environment` subclass | Required | `RangeEnvironment(Environment[RangeAction, RangeObservation, RangeState])` |
| `reset()` returns `ObsT` | Required | Returns `RangeObservation` |
| `step()` returns `ObsT` | Required | Returns `RangeObservation` |
| `state` property returns `StateT` | Required | Returns `RangeState` |
| `Action` subclass (Pydantic, extra=forbid) | Required | `RangeAction(Action)` with `command`, `mode` |
| `Observation` subclass (Pydantic, extra=forbid) | Required | `RangeObservation(Observation)` — inherits `done`, `reward` from base |
| `State` subclass (Pydantic, extra=allow) | Required | `RangeState(State)` — inherits `episode_id`, `step_count` from base |
| `create_app(Class, ActionType, ObsType)` | Required | Pass CLASS not instance |
| `EnvClient` subclass | Required | `OpenRangeEnv(EnvClient[...])` |
| `_step_payload()` | Required | Serializes `RangeAction` to dict |
| `_parse_result()` | Required | Parses server response to `StepResult[RangeObservation]` |
| `_parse_state()` | Required | Parses server response to `RangeState` |
| `/health` endpoint | Auto | Provided by `create_app` |
| `/ws` WebSocket | Auto | Provided by `create_app` |
| `/reset`, `/step`, `/state` HTTP | Auto | Provided by `create_app` |
| `Rubric` for rewards | Optional | `CompositeRedReward`, `CompositeBlueReward` as Rubric subclasses |
| `openenv.yaml` manifest | Required | Environment metadata for HF Spaces |
| `Dockerfile` | Required | For container deployment |

## Common Mistakes to Avoid

1. **Don't redeclare `done` or `reward` on Observation.** The base class already has them.
2. **Don't redeclare `episode_id` or `step_count` on State.** The base class already has them.
3. **Pass the CLASS to `create_app()`, not an instance.** Each WebSocket session gets its own instance.
4. **Action uses `extra="forbid"`.** Unknown fields cause validation errors. Keep actions minimal.
5. **State uses `extra="allow"`.** You can add any fields you want.
6. **`reset()` returns ObsT (server-side), `StepResult[ObsT]` (client-side).** The server wraps it.

## API Signatures (Exact)

```python
# Server-side
class RangeEnvironment(Environment[RangeAction, RangeObservation, RangeState]):
    def reset(self, seed: Optional[int] = None,
              episode_id: Optional[str] = None, **kwargs) -> RangeObservation: ...
    def step(self, action: RangeAction,
             timeout_s: Optional[float] = None, **kwargs) -> RangeObservation: ...
    @property
    def state(self) -> RangeState: ...

# Client-side
class OpenRangeEnv(EnvClient[RangeAction, RangeObservation, RangeState]):
    def _step_payload(self, action: RangeAction) -> dict: ...
    def _parse_result(self, payload: dict) -> StepResult[RangeObservation]: ...
    def _parse_state(self, payload: dict) -> RangeState: ...

# App factory
app = create_app(RangeEnvironment, RangeAction, RangeObservation, env_name="open_range")
```

## Reference Implementations

Study these OpenEnv environments as patterns:

- **`envs/coding_env/`** — closest analog (execute code, get stdout/stderr). Uses `Environment` base.
- **`envs/echo_env/`** — simplest possible environment. Uses `MCPEnvironment` base.
- **`envs/finqa_env/`** — MCP tool-based with complex rewards. Uses `MCPEnvironment` base.
