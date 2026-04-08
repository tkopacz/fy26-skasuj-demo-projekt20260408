"""
HTTP health and metrics server for the tactical relay service.

Binds to localhost only. Provides:
  GET /health  — JSON health report
  GET /metrics — Prometheus text format metrics
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import timezone
from typing import TYPE_CHECKING, Optional

from aiohttp import web

if TYPE_CHECKING:
    from tactical_relay.transport import TLSServer
    from tactical_relay.queues import QueueManager
    from tactical_relay.audit import AuditLogger

logger = logging.getLogger(__name__)


def _cert_expiry_days(certfile: str) -> Optional[float]:
    """
    Return days until the certificate in certfile expires, or None on error.

    Args:
        certfile: Path to a PEM-encoded certificate file.

    Returns:
        Fractional days until expiry, or None if the file cannot be read.
    """
    import datetime as _dt

    try:
        from cryptography import x509
        from pathlib import Path

        data = Path(certfile).read_bytes()
        cert = x509.load_pem_x509_certificate(data)
        # not_valid_after_utc added in cryptography 42; fall back to not_valid_after
        not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
        now = _dt.datetime.now(tz=timezone.utc)
        # Ensure not_after is timezone-aware for subtraction
        if not_after.tzinfo is None:
            not_after = not_after.replace(tzinfo=_dt.timezone.utc)
        delta = not_after - now
        return delta.total_seconds() / 86400.0
    except Exception as exc:
        logger.debug("Could not read cert expiry from %s: %s", certfile, exc)
        return None


class HealthServer:
    """
    Lightweight HTTP server providing health and metrics endpoints.

    Binds exclusively to 127.0.0.1 to prevent external exposure.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        tls_server: Optional["TLSServer"] = None,
        queue_manager: Optional["QueueManager"] = None,
        audit_logger: Optional["AuditLogger"] = None,
        certfile: Optional[str] = None,
    ) -> None:
        """
        Initialise the HealthServer.

        Args:
            host: Bind address (should be 127.0.0.1).
            port: HTTP port to listen on.
            tls_server: Reference to the TLSServer for connection metrics.
            queue_manager: Reference to QueueManager for queue depth metrics.
            audit_logger: Reference to AuditLogger for event counts.
            certfile: Path to server cert for expiry calculation.
        """
        self._host = host
        self._port = port
        self._tls = tls_server
        self._queues = queue_manager
        self._audit = audit_logger
        self._certfile = certfile
        self._start_time = time.time()
        self._runner: Optional[web.AppRunner] = None

    async def start(self) -> None:
        """Start the health HTTP server."""
        app = web.Application()
        app.router.add_get("/health", self._handle_health)
        app.router.add_get("/metrics", self._handle_metrics)

        self._runner = web.AppRunner(app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, host=self._host, port=self._port)
        await site.start()
        logger.info("Health server listening on http://%s:%d", self._host, self._port)

    async def stop(self) -> None:
        """Stop the health HTTP server."""
        if self._runner:
            await self._runner.cleanup()
            logger.info("Health server stopped")

    # ------------------------------------------------------------------
    # Endpoint handlers
    # ------------------------------------------------------------------

    async def _handle_health(self, request: web.Request) -> web.Response:
        """
        Return a JSON health report.

        Response body::

            {
              "status": "ok",
              "uptime_seconds": 12345.6,
              "active_connections": 3,
              "queue_depths": {"HQ-PRIMARY": 10},
              "messages_processed": 42,
              "error_counts": {"parse_error": 1},
              "cert_expiry_days": 89.5
            }
        """
        data = self._collect_data()
        return web.json_response(data)

    async def _handle_metrics(self, request: web.Request) -> web.Response:
        """Return metrics in Prometheus text exposition format."""
        data = self._collect_data()
        lines: list[str] = []

        def gauge(name: str, value: float, labels: str = "") -> None:
            label_str = f"{{{labels}}}" if labels else ""
            lines.append(f"# TYPE {name} gauge")
            lines.append(f"{name}{label_str} {value}")

        gauge("relay_uptime_seconds", data["uptime_seconds"])
        gauge("relay_active_connections", data["active_connections"])
        gauge("relay_messages_processed_total", data["messages_processed"])

        for queue_name, depth in data["queue_depths"].items():
            safe_name = queue_name.replace("-", "_").replace(".", "_")
            gauge(
                "relay_queue_depth",
                depth,
                labels=f'recipient="{queue_name}"',
            )

        for error_type, count in data["error_counts"].items():
            gauge(
                "relay_errors_total",
                count,
                labels=f'type="{error_type}"',
            )

        if data["cert_expiry_days"] is not None:
            gauge("relay_cert_expiry_days", data["cert_expiry_days"])

        text = "\n".join(lines) + "\n"
        return web.Response(text=text, content_type="text/plain")

    # ------------------------------------------------------------------
    # Data collection
    # ------------------------------------------------------------------

    def _collect_data(self) -> dict:
        """Collect and return a snapshot of all health metrics."""
        uptime = time.time() - self._start_time

        active_connections = 0
        messages_processed = 0
        error_counts: dict = {}
        if self._tls is not None:
            active_connections = self._tls.active_connections
            messages_processed = self._tls.messages_processed
            error_counts = self._tls.error_counts

        queue_depths: dict = {}
        if self._queues is not None:
            metrics = self._queues.get_all_metrics()
            queue_depths = metrics.get("per_queue_depths", {})

        cert_expiry_days = None
        if self._certfile:
            cert_expiry_days = _cert_expiry_days(self._certfile)

        return {
            "status": "ok",
            "uptime_seconds": round(uptime, 2),
            "active_connections": active_connections,
            "queue_depths": queue_depths,
            "messages_processed": messages_processed,
            "error_counts": error_counts,
            "cert_expiry_days": cert_expiry_days,
        }
