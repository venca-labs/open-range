"""Tests for the episode dashboard components."""

from __future__ import annotations

import asyncio

from open_range.dashboard.bridge import EventBridge
from open_range.dashboard.narrator import fallback_narrate
from open_range.runtime_types import RuntimeEvent


def _make_event(
    *,
    event_type: str = "InitialAccess",
    actor: str = "red",
    source: str = "agent-red",
    target: str = "svc-web",
    malicious: bool = True,
    time: float = 1.0,
    event_id: str = "evt-1",
) -> RuntimeEvent:
    return RuntimeEvent(
        id=event_id,
        event_type=event_type,
        actor=actor,
        time=time,
        source_entity=source,
        target_entity=target,
        malicious=malicious,
    )


class TestEventBridge:
    def test_push_and_snapshot(self):
        bridge = EventBridge(max_buffer=5)
        events = [_make_event(event_id=f"evt-{i}", time=float(i)) for i in range(3)]
        for ev in events:
            bridge.push(ev)

        buf = bridge.snapshot_buffer()
        assert len(buf) == 3
        assert buf[0].id == "evt-0"
        assert buf[2].id == "evt-2"

    def test_buffer_overflow(self):
        bridge = EventBridge(max_buffer=3)
        for i in range(10):
            bridge.push(_make_event(event_id=f"evt-{i}", time=float(i)))

        buf = bridge.snapshot_buffer()
        assert len(buf) == 3
        assert buf[0].id == "evt-7"

    def test_subscribe_receives_backlog_and_live(self):
        bridge = EventBridge(max_buffer=100)
        bridge.push(_make_event(event_id="backlog-1", time=0.0))
        bridge.push(_make_event(event_id="backlog-2", time=1.0))

        received: list[RuntimeEvent] = []

        async def run():
            sub = bridge.subscribe()
            # Get backlog
            ev1 = await sub.__anext__()
            received.append(ev1)
            ev2 = await sub.__anext__()
            received.append(ev2)

            # Push a live event
            bridge.push(_make_event(event_id="live-1", time=2.0))
            ev3 = await sub.__anext__()
            received.append(ev3)

            # Close
            bridge.close()
            async for _ in sub:
                pass

        asyncio.run(run())

        assert len(received) == 3
        assert received[0].id == "backlog-1"
        assert received[1].id == "backlog-2"
        assert received[2].id == "live-1"

    def test_close_signals_subscribers(self):
        bridge = EventBridge()

        async def run():
            collected: list[RuntimeEvent] = []

            async def consume():
                async for ev in bridge.subscribe():
                    collected.append(ev)

            task = asyncio.create_task(consume())
            await asyncio.sleep(0.05)  # let generator register
            bridge.close()
            await asyncio.wait_for(task, timeout=2.0)
            return collected

        result = asyncio.run(run())
        assert result == []


class TestFallbackNarrator:
    def test_empty_events(self):
        result = fallback_narrate([])
        assert result == ""

    def test_basic_narration(self):
        events = [
            _make_event(actor="red", event_type="InitialAccess", target="svc-web"),
            _make_event(
                actor="blue",
                event_type="DetectionAlertRaised",
                target="svc-siem",
                malicious=False,
            ),
        ]
        text = fallback_narrate(events)
        assert "Red" in text
        assert "Blue" in text
        assert "svc-web" in text
        assert "🔴" in text
        assert "🔵" in text

    def test_malicious_gets_warning(self):
        events = [
            _make_event(actor="red", event_type="InitialAccess", malicious=True),
        ]
        text = fallback_narrate(events)
        assert "⚠️" in text

    def test_green_user_action(self):
        events = [
            _make_event(
                actor="green",
                event_type="BenignUserAction",
                source="user-sarah",
                target="svc-web",
                malicious=False,
            ),
        ]
        text = fallback_narrate(events)
        assert "Green" in text
        assert "🟢" in text


class TestTopologyExtraction:
    """Test that topology extraction logic produces the right shape."""

    def test_topology_shape(self):
        """Verify the extraction logic produces correct structure from raw data."""
        # Simulate the raw data the app would extract
        hosts = [
            {"id": "web-host", "zone": "dmz"},
            {"id": "db-host", "zone": "internal"},
        ]
        services_raw = [
            {"id": "svc-web", "kind": "web_app", "host": "web-host", "ports": [443]},
            {"id": "svc-db", "kind": "database", "host": "db-host", "ports": [5432]},
        ]
        edges_raw = [{"source": "svc-web", "target": "svc-db", "kind": "data"}]

        host_zone = {h["id"]: h["zone"] for h in hosts}

        services = []
        zone_set: set[str] = set()
        for svc in services_raw:
            zone = host_zone.get(svc["host"], "unknown")
            zone_set.add(zone)
            services.append(
                {
                    "id": svc["id"],
                    "kind": svc["kind"],
                    "host": svc["host"],
                    "zone": zone,
                    "ports": svc["ports"],
                }
            )

        topo = {
            "services": services,
            "edges": edges_raw,
            "zones": sorted(zone_set),
        }

        assert len(topo["services"]) == 2
        assert topo["services"][0]["id"] == "svc-web"
        assert topo["services"][0]["zone"] == "dmz"
        assert len(topo["edges"]) == 1
        assert topo["edges"][0]["source"] == "svc-web"
        assert set(topo["zones"]) == {"dmz", "internal"}

