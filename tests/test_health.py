"""Tests for the health server module."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from aiohttp import web

from tactical_relay.health import HealthServer


@pytest.fixture
def mock_tls_server():
    """Stub TLS server providing metrics."""
    s = MagicMock()
    s.active_connections = 3
    s.messages_processed = 42
    s.error_counts = {"parse_error": 1}
    return s


@pytest.fixture
def mock_queue_manager():
    """Stub queue manager providing queue depths."""
    qm = MagicMock()
    qm.get_all_metrics.return_value = {
        "per_queue_depths": {"HQ-PRIMARY": 10, "HQ-BACKUP": 2},
        "total_delivered": 100,
        "total_expired": 5,
        "total_pending": 12,
    }
    return qm


@pytest.fixture
def health_server(mock_tls_server, mock_queue_manager):
    """HealthServer instance with mocked dependencies."""
    return HealthServer(
        host="127.0.0.1",
        port=0,
        tls_server=mock_tls_server,
        queue_manager=mock_queue_manager,
        audit_logger=None,
        certfile=None,
    )


@pytest.fixture
def health_app(health_server):
    """aiohttp Application with health routes registered."""
    app = web.Application()
    app.router.add_get("/health", health_server._handle_health)
    app.router.add_get("/metrics", health_server._handle_metrics)
    return app


class TestHealthEndpoint:
    """Tests for the /health endpoint."""

    async def test_health_returns_ok_status(self, aiohttp_client, health_app):
        client = await aiohttp_client(health_app)
        resp = await client.get("/health")
        assert resp.status == 200
        data = await resp.json()
        assert data["status"] == "ok"

    async def test_health_contains_required_fields(self, aiohttp_client, health_app):
        client = await aiohttp_client(health_app)
        resp = await client.get("/health")
        data = await resp.json()
        required = {
            "status", "uptime_seconds", "active_connections",
            "queue_depths", "messages_processed", "error_counts",
            "cert_expiry_days",
        }
        assert required.issubset(data.keys())

    async def test_health_reflects_tls_metrics(self, aiohttp_client, health_app):
        client = await aiohttp_client(health_app)
        resp = await client.get("/health")
        data = await resp.json()
        assert data["active_connections"] == 3
        assert data["messages_processed"] == 42
        assert data["error_counts"] == {"parse_error": 1}

    async def test_health_reflects_queue_depths(self, aiohttp_client, health_app):
        client = await aiohttp_client(health_app)
        resp = await client.get("/health")
        data = await resp.json()
        assert data["queue_depths"]["HQ-PRIMARY"] == 10
        assert data["queue_depths"]["HQ-BACKUP"] == 2

    async def test_health_uptime_positive(self, aiohttp_client, health_app):
        client = await aiohttp_client(health_app)
        resp = await client.get("/health")
        data = await resp.json()
        assert data["uptime_seconds"] >= 0


class TestMetricsEndpoint:
    """Tests for the /metrics endpoint."""

    async def test_metrics_returns_text_plain(self, aiohttp_client, health_app):
        client = await aiohttp_client(health_app)
        resp = await client.get("/metrics")
        assert resp.status == 200
        assert "text/plain" in resp.content_type

    async def test_metrics_contains_gauge_definitions(self, aiohttp_client, health_app):
        client = await aiohttp_client(health_app)
        resp = await client.get("/metrics")
        text = await resp.text()
        assert "relay_uptime_seconds" in text
        assert "relay_active_connections" in text
        assert "relay_messages_processed_total" in text

    async def test_metrics_contains_queue_depth(self, aiohttp_client, health_app):
        client = await aiohttp_client(health_app)
        resp = await client.get("/metrics")
        text = await resp.text()
        assert "relay_queue_depth" in text

    async def test_metrics_prometheus_format(self, aiohttp_client, health_app):
        """Verify each metric has a TYPE comment line."""
        client = await aiohttp_client(health_app)
        resp = await client.get("/metrics")
        text = await resp.text()
        assert "# TYPE relay_uptime_seconds gauge" in text

