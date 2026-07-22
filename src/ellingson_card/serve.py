"""Serve a signed Agent Card locally at the v1.0 well-known path.

The card is served locally; the DNSSEC/CT delivery-channel attestation is
documented and diagrammed against the real pattern rather than live-served.
See ``docs/delivery-hardening.md`` (serving model) for the rationale.
Security headers (HSTS, nosniff) mirror the documented production posture.
Uses the stdlib HTTP server — no web framework dependency.
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from ellingson_card.card import CardError

WELL_KNOWN_PATH = "/.well-known/agent-card.json"


def make_server(card_path: Path, port: int) -> ThreadingHTTPServer:
    """Build an HTTP server that serves the card at the well-known path.

    Args:
        card_path: Path to the signed card JSON to serve.
        port: TCP port to bind (0 selects an ephemeral port).

    Returns:
        An unstarted ``ThreadingHTTPServer``; call ``serve_forever`` to run it.

    Raises:
        CardError: If the card file cannot be read.
        OSError: If the port cannot be bound.
    """
    try:
        card_bytes = card_path.read_bytes()
    except OSError as exc:
        raise CardError(f"cannot read card {card_path}: {exc}") from exc

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 (stdlib-required name)
            if self.path != WELL_KNOWN_PATH:
                self.send_error(404, "not found")
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(card_bytes)))
            self.send_header("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(card_bytes)

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            """Silence default request logging."""

    return ThreadingHTTPServer(("127.0.0.1", port), _Handler)
