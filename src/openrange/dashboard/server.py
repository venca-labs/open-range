"""HTTP server that exposes a DashboardView and serves the SPA frontend."""

from __future__ import annotations

import json
from collections.abc import Mapping
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import cast
from urllib.parse import urlsplit

from openrange.dashboard.view import DashboardView

STATIC_ROOT = Path(__file__).parent / "static"

STATIC_CONTENT_TYPES: Mapping[str, str] = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
}


class DashboardHTTPServer(ThreadingHTTPServer):
    def __init__(
        self,
        server_address: tuple[str, int],
        view: DashboardView,
    ) -> None:
        self.view = view
        super().__init__(server_address, DashboardRequestHandler)


class DashboardRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/":
            self._write_static("index.html")
            return
        if path.startswith("/static/"):
            self._write_static(path[len("/static/") :])
            return
        if path == "/api/events/stream":
            self._stream_events()
            return
        if path == "/api/narrate/stream":
            self._stream_narration()
            return

        routes = {
            "/api/briefing": self.view.briefing,
            "/api/actors": self.view.actors,
            "/api/topology": self.view.topology,
            "/api/lineage": self.view.lineage,
            "/api/state": self.view.state,
            "/api/inspect": self.view.inspect,
            "/api/narrate": self.view.narration,
        }
        route = routes.get(path)
        if route is None:
            self._write_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
            return
        self._write_json(route())

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        routes = {
            "/api/episode/reset": self.view.reset,
            "/api/episode/play": self.view.play,
            "/api/episode/pause": self.view.pause,
        }
        route = routes.get(path)
        if route is None:
            self._write_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
            return
        self._write_json(route())

    @property
    def view(self) -> DashboardView:
        return cast(DashboardHTTPServer, self.server).view

    def _write_static(self, relative: str) -> None:
        target = (STATIC_ROOT / relative).resolve()
        if STATIC_ROOT.resolve() not in target.parents or not target.is_file():
            self._write_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
            return
        content_type = STATIC_CONTENT_TYPES.get(
            target.suffix,
            "application/octet-stream",
        )
        body = target.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _write_json(
        self,
        payload: object,
        status: HTTPStatus = HTTPStatus.OK,
    ) -> None:
        body = json.dumps(payload, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _stream_events(self) -> None:
        self._write_sse_headers()
        for event in self.view.bridge.subscribe_sync():
            self._write_sse(event.as_dict(), event=event.type, event_id=event.id)

    def _stream_narration(self) -> None:
        self._write_sse_headers()
        for event in self.view.bridge.subscribe_sync():
            self._write_sse(
                self.view.narration(),
                event="narration",
                event_id=event.id,
            )

    def _write_sse_headers(self) -> None:
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()

    def _write_sse(
        self,
        payload: Mapping[str, object],
        *,
        event: str,
        event_id: str,
    ) -> None:
        body = (
            f"id: {event_id}\n"
            f"event: {event}\n"
            f"data: {json.dumps(payload, sort_keys=True)}\n\n"
        ).encode()
        try:
            self.wfile.write(body)
            self.wfile.flush()
        except BrokenPipeError:  # pragma: no cover - depends on client timing.
            return

    def log_message(self, format: str, *args: object) -> None:
        return
