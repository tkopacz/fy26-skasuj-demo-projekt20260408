"""
Configuration management for the tactical relay service.

All settings can be overridden via environment variables with the RELAY_ prefix.
Example: RELAY_TRANSPORT_PORT=8443 overrides transport.port.
"""

from __future__ import annotations

import os
import logging
from dataclasses import dataclass, field
from typing import Optional

import yaml

logger = logging.getLogger(__name__)


@dataclass
class TransportConfig:
    """TLS transport layer configuration."""

    # Hostname or IP to bind to
    host: str = "0.0.0.0"
    # TCP port for the TLS server
    port: int = 8443
    # Path to the server TLS certificate (PEM)
    certfile: str = "certs/server.crt"
    # Path to the server TLS private key (PEM)
    keyfile: str = "certs/server.key"
    # Path to the CA bundle for client certificate verification (PEM)
    ca_bundle: str = "certs/ca.crt"
    # Maximum incoming messages per second per IP address
    rate_limit_per_ip: int = 100
    # Maximum simultaneous connections
    max_connections: int = 1000


@dataclass
class AuthConfig:
    """Authentication and authorization configuration."""

    # Path to the SQLite database containing authorized senders
    db_path: str = "data/auth.db"
    # Path to the PEM-encoded Certificate Revocation List
    crl_path: str = "certs/ca.crl"


@dataclass
class QueuesConfig:
    """Message queue configuration."""

    # Path to the SQLite database for persistent queues
    db_path: str = "data/queues.db"
    # Maximum number of messages in a single recipient queue
    max_depth_per_queue: int = 10_000
    # Default TTL in seconds (0 = no expiry)
    default_ttl_seconds: int = 3600


@dataclass
class AuditConfig:
    """Audit logging configuration."""

    # Path to the structured audit log file
    log_path: str = "logs/audit.jsonl"
    # Maximum size of a single log file in bytes before rotation
    max_bytes: int = 100 * 1024 * 1024  # 100 MB
    # Number of rotated backup files to keep
    backup_count: int = 10
    # HMAC secret for chain integrity (MUST be set via RELAY_AUDIT_HMAC_SECRET env var)
    hmac_secret: str = ""


@dataclass
class HealthConfig:
    """HTTP health endpoint configuration."""

    # Health server bind address (should be localhost only)
    host: str = "127.0.0.1"
    # Health server HTTP port
    port: int = 8080


@dataclass
class RoutingConfig:
    """Message routing configuration."""

    # Path to the YAML routing rules file
    rules_file: str = "config/routing_rules.yaml"


@dataclass
class ServiceConfig:
    """
    Top-level service configuration.

    Load from a YAML file and override individual settings via environment
    variables using the RELAY_ prefix with single-underscore separators.
    Example: RELAY_TRANSPORT_PORT=9443
    """

    transport: TransportConfig = field(default_factory=TransportConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    queues: QueuesConfig = field(default_factory=QueuesConfig)
    audit: AuditConfig = field(default_factory=AuditConfig)
    health: HealthConfig = field(default_factory=HealthConfig)
    routing: RoutingConfig = field(default_factory=RoutingConfig)
    # Python logging level: DEBUG, INFO, WARNING, ERROR, CRITICAL
    log_level: str = "INFO"


def _apply_env_overrides(config: ServiceConfig) -> None:
    """
    Apply environment variable overrides to the config.

    Environment variables use the format RELAY_<SECTION>_<KEY> where section
    and key are uppercase. For example, RELAY_TRANSPORT_PORT=9443 sets
    config.transport.port = 9443.
    """
    prefix = "RELAY_"
    section_map = {
        "TRANSPORT": config.transport,
        "AUTH": config.auth,
        "QUEUES": config.queues,
        "AUDIT": config.audit,
        "HEALTH": config.health,
        "ROUTING": config.routing,
    }

    for env_key, env_val in os.environ.items():
        if not env_key.startswith(prefix):
            continue
        rest = env_key[len(prefix):]
        parts = rest.split("_", 1)
        if len(parts) == 2:
            section_name, attr_name = parts[0], parts[1].lower()
            if section_name in section_map:
                obj = section_map[section_name]
                if hasattr(obj, attr_name):
                    current = getattr(obj, attr_name)
                    try:
                        if isinstance(current, bool):
                            setattr(obj, attr_name, env_val.lower() in ("1", "true", "yes"))
                        elif isinstance(current, int):
                            setattr(obj, attr_name, int(env_val))
                        elif isinstance(current, float):
                            setattr(obj, attr_name, float(env_val))
                        else:
                            setattr(obj, attr_name, env_val)
                    except (ValueError, TypeError) as exc:
                        raise ValueError(
                            f"Invalid value for {env_key}: {env_val!r} — {exc}"
                        ) from exc

    # Special case: RELAY_LOG_LEVEL
    if "RELAY_LOG_LEVEL" in os.environ:
        config.log_level = os.environ["RELAY_LOG_LEVEL"]

    # HMAC secret must come from environment
    hmac_secret = os.environ.get("RELAY_AUDIT_HMAC_SECRET", "")
    if hmac_secret:
        config.audit.hmac_secret = hmac_secret


def _validate(config: ServiceConfig) -> None:
    """
    Validate all configuration settings.

    Raises ValueError with a descriptive message if any setting is invalid.
    """
    # Transport
    if not (1 <= config.transport.port <= 65535):
        raise ValueError(
            f"transport.port must be 1-65535, got {config.transport.port}"
        )
    if config.transport.rate_limit_per_ip <= 0:
        raise ValueError("transport.rate_limit_per_ip must be > 0")
    if config.transport.max_connections <= 0:
        raise ValueError("transport.max_connections must be > 0")

    # Auth
    if not config.auth.db_path:
        raise ValueError("auth.db_path must not be empty")

    # Queues
    if config.queues.max_depth_per_queue <= 0:
        raise ValueError("queues.max_depth_per_queue must be > 0")
    if config.queues.default_ttl_seconds < 0:
        raise ValueError("queues.default_ttl_seconds must be >= 0")

    # Audit
    if config.audit.max_bytes <= 0:
        raise ValueError("audit.max_bytes must be > 0")
    if config.audit.backup_count < 0:
        raise ValueError("audit.backup_count must be >= 0")

    # Health
    if not (1 <= config.health.port <= 65535):
        raise ValueError(
            f"health.port must be 1-65535, got {config.health.port}"
        )

    # Log level
    valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
    if config.log_level.upper() not in valid_levels:
        raise ValueError(
            f"log_level must be one of {valid_levels}, got {config.log_level!r}"
        )

    logger.debug("Configuration validated successfully")


def load_config(config_path: Optional[str] = None) -> ServiceConfig:
    """
    Load ServiceConfig from a YAML file and apply environment variable overrides.

    Args:
        config_path: Path to the YAML configuration file. If None, defaults are used.

    Returns:
        A validated ServiceConfig instance.

    Raises:
        ValueError: If any configuration setting is invalid.
        FileNotFoundError: If config_path is given but does not exist.
    """
    config = ServiceConfig()

    if config_path is not None:
        with open(config_path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}

        transport_raw = raw.get("transport", {})
        for key, val in transport_raw.items():
            if hasattr(config.transport, key):
                setattr(config.transport, key, val)

        auth_raw = raw.get("auth", {})
        for key, val in auth_raw.items():
            if hasattr(config.auth, key):
                setattr(config.auth, key, val)

        queues_raw = raw.get("queues", {})
        for key, val in queues_raw.items():
            if hasattr(config.queues, key):
                setattr(config.queues, key, val)

        audit_raw = raw.get("audit", {})
        for key, val in audit_raw.items():
            if hasattr(config.audit, key):
                setattr(config.audit, key, val)

        health_raw = raw.get("health", {})
        for key, val in health_raw.items():
            if hasattr(config.health, key):
                setattr(config.health, key, val)

        routing_raw = raw.get("routing", {})
        for key, val in routing_raw.items():
            if hasattr(config.routing, key):
                setattr(config.routing, key, val)

        if "log_level" in raw:
            config.log_level = raw["log_level"]

    _apply_env_overrides(config)
    _validate(config)
    return config
