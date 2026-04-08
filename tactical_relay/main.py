"""
Entry point for the tactical relay service.

Usage:
    python -m tactical_relay.main --config config.yaml
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal
import sys
from pathlib import Path

from tactical_relay.audit import AuditLogger
from tactical_relay.auth import AuthManager
from tactical_relay.config import load_config
from tactical_relay.health import HealthServer
from tactical_relay.queues import QueueManager
from tactical_relay.router import RoutingEngine
from tactical_relay.transport import TLSServer

logger = logging.getLogger(__name__)


def _configure_logging(log_level: str) -> None:
    """Configure root logger with the given level."""
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )


async def main() -> None:
    """
    Async entry point for the tactical relay service.

    Loads configuration, initialises all subsystems, starts the TLS transport
    and health servers, and handles SIGTERM/SIGINT for graceful shutdown.
    """
    parser = argparse.ArgumentParser(description="Tactical Message Relay Service")
    parser.add_argument(
        "--config",
        default="config.yaml",
        help="Path to YAML configuration file (default: config.yaml)",
    )
    args = parser.parse_args()

    # Load configuration
    config_path = args.config if Path(args.config).exists() else None
    config = load_config(config_path)
    _configure_logging(config.log_level)

    logger.info("Starting tactical relay service v0.1.0")

    # Ensure data directories exist
    for path_str in [config.auth.db_path, config.queues.db_path, config.audit.log_path]:
        Path(path_str).parent.mkdir(parents=True, exist_ok=True)

    # Validate HMAC secret
    hmac_secret = os.environ.get("RELAY_AUDIT_HMAC_SECRET", config.audit.hmac_secret)
    if not hmac_secret:
        logger.error(
            "RELAY_AUDIT_HMAC_SECRET environment variable is required but not set. "
            "Generate a strong secret and export it before starting the service."
        )
        sys.exit(1)

    # Initialise subsystems
    audit = AuditLogger(
        log_path=config.audit.log_path,
        hmac_secret=hmac_secret,
        max_bytes=config.audit.max_bytes,
        backup_count=config.audit.backup_count,
    )

    auth_mgr = AuthManager(db_path=config.auth.db_path, crl_path=config.auth.crl_path)
    auth_mgr.initialize_db()

    queue_mgr = QueueManager(
        db_path=config.queues.db_path,
        max_depth_per_queue=config.queues.max_depth_per_queue,
        default_ttl_seconds=config.queues.default_ttl_seconds,
    )

    if Path(config.routing.rules_file).exists():
        router = RoutingEngine.from_file(config.routing.rules_file)
    else:
        logger.warning(
            "Routing rules file not found: %s — using empty rule set (all messages → DLQ)",
            config.routing.rules_file,
        )
        router = RoutingEngine(rules=[])

    tls_server = TLSServer(
        host=config.transport.host,
        port=config.transport.port,
        certfile=config.transport.certfile,
        keyfile=config.transport.keyfile,
        ca_bundle=config.transport.ca_bundle,
        auth_manager=auth_mgr,
        queue_manager=queue_mgr,
        routing_engine=router,
        audit_logger=audit,
        rate_limit_per_ip=config.transport.rate_limit_per_ip,
        max_connections=config.transport.max_connections,
    )

    health_server = HealthServer(
        host=config.health.host,
        port=config.health.port,
        tls_server=tls_server,
        queue_manager=queue_mgr,
        audit_logger=audit,
        certfile=config.transport.certfile,
    )

    # Start servers
    await tls_server.start()
    await health_server.start()

    # Graceful shutdown on SIGTERM / SIGINT
    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    def _signal_handler() -> None:
        logger.info("Shutdown signal received")
        stop_event.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, _signal_handler)

    logger.info(
        "Relay service ready — TLS on %s:%d, health on %s:%d",
        config.transport.host,
        config.transport.port,
        config.health.host,
        config.health.port,
    )

    await stop_event.wait()

    # Shutdown
    logger.info("Shutting down gracefully…")
    await tls_server.stop()
    await health_server.stop()
    auth_mgr.close()
    queue_mgr.close()
    logger.info("Shutdown complete")


if __name__ == "__main__":
    asyncio.run(main())
