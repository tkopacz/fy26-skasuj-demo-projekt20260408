"""
Pytest fixtures shared across all test modules.

Uses real SQLite databases, real crypto objects, and real YAML files.
No mocking — all fixtures are backed by actual implementations.
"""

from __future__ import annotations

import datetime
import os
import textwrap
from pathlib import Path
from typing import Generator

import pytest
import yaml

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from tactical_relay.audit import AuditLogger
from tactical_relay.auth import AuthManager
from tactical_relay.config import (
    AuditConfig,
    AuthConfig,
    HealthConfig,
    QueuesConfig,
    RoutingConfig,
    ServiceConfig,
    TransportConfig,
)
from tactical_relay.queues import QueueManager
from tactical_relay.router import RoutingEngine


# ---------------------------------------------------------------------------
# Database / path fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_db(tmp_path: Path) -> Path:
    """Return a path to a temporary SQLite database file."""
    return tmp_path / "test.db"


# ---------------------------------------------------------------------------
# Configuration fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def test_config(tmp_path: Path) -> ServiceConfig:
    """Return a ServiceConfig with all paths pointing to tmp_path."""
    cfg = ServiceConfig(
        transport=TransportConfig(
            host="127.0.0.1",
            port=19443,
            certfile=str(tmp_path / "server.crt"),
            keyfile=str(tmp_path / "server.key"),
            ca_bundle=str(tmp_path / "ca.crt"),
            rate_limit_per_ip=50,
            max_connections=10,
        ),
        auth=AuthConfig(
            db_path=str(tmp_path / "auth.db"),
            crl_path=str(tmp_path / "ca.crl"),
        ),
        queues=QueuesConfig(
            db_path=str(tmp_path / "queues.db"),
            max_depth_per_queue=100,
            default_ttl_seconds=60,
        ),
        audit=AuditConfig(
            log_path=str(tmp_path / "audit.jsonl"),
            max_bytes=1024 * 1024,
            backup_count=3,
            hmac_secret="test-hmac-secret-for-testing-only",
        ),
        health=HealthConfig(host="127.0.0.1", port=19080),
        routing=RoutingConfig(rules_file=str(tmp_path / "rules.yaml")),
        log_level="DEBUG",
    )
    return cfg


# ---------------------------------------------------------------------------
# Audit logger fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def audit_logger(tmp_path: Path) -> AuditLogger:
    """Return a real AuditLogger writing to a temporary file."""
    return AuditLogger(
        log_path=str(tmp_path / "audit.jsonl"),
        hmac_secret="test-hmac-secret-for-testing-only",
        max_bytes=1024 * 1024,
        backup_count=2,
    )


# ---------------------------------------------------------------------------
# Queue manager fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def queue_manager(tmp_path: Path) -> Generator[QueueManager, None, None]:
    """Return a QueueManager backed by a temporary SQLite database."""
    qm = QueueManager(
        db_path=str(tmp_path / "queues.db"),
        max_depth_per_queue=10,
        default_ttl_seconds=3600,
    )
    yield qm
    qm.close()


# ---------------------------------------------------------------------------
# Auth manager fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def auth_manager(tmp_path: Path) -> Generator[AuthManager, None, None]:
    """Return an AuthManager with test data pre-loaded."""
    mgr = AuthManager(
        db_path=str(tmp_path / "auth.db"),
        crl_path=None,
    )
    mgr.initialize_db()
    yield mgr
    mgr.close()


# ---------------------------------------------------------------------------
# Routing engine fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def routing_engine(tmp_path: Path) -> RoutingEngine:
    """Return a RoutingEngine with sample routing rules."""
    rules_data = {
        "rules": [
            {
                "name": "urgent-high-command",
                "match": {
                    "priority_max": 2,
                    "classification": "TOP_SECRET",
                    "originator_pattern": "FIELD-*",
                },
                "action": {
                    "type": "multicast",
                    "recipients": ["HQ-PRIMARY", "HQ-BACKUP"],
                },
            },
            {
                "name": "confidential-relay",
                "match": {
                    "classification": "CONFIDENTIAL",
                },
                "action": {
                    "type": "direct",
                    "recipients": ["RELAY-NODE-1"],
                },
            },
            {
                "name": "default",
                "match": {},
                "action": {
                    "type": "direct",
                    "recipients": ["DEFAULT-QUEUE"],
                },
            },
        ]
    }
    rules_file = tmp_path / "rules.yaml"
    rules_file.write_text(yaml.dump(rules_data), encoding="utf-8")
    return RoutingEngine.from_file(str(rules_file))


# ---------------------------------------------------------------------------
# Certificate fixtures
# ---------------------------------------------------------------------------

def _make_key() -> rsa.RSAPrivateKey:
    """Generate a 2048-bit RSA private key."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _make_ca_cert(key: rsa.RSAPrivateKey) -> x509.Certificate:
    """Create a self-signed CA certificate."""
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Test-CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TacticalRelay-Test"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(seconds=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )


def _make_client_cert(
    cn: str,
    ou: str,
    ca_cert: x509.Certificate,
    ca_key: rsa.RSAPrivateKey,
    serial: int = 1000,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Generate a client key and certificate signed by the given CA."""
    client_key = _make_key()
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(client_key.public_key())
        .serial_number(serial)
        .not_valid_before(now - datetime.timedelta(seconds=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    return client_key, cert


@pytest.fixture
def ca_cert_and_key() -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    """Generate a test CA certificate and private key."""
    key = _make_key()
    cert = _make_ca_cert(key)
    return cert, key


@pytest.fixture
def client_cert_and_key(
    ca_cert_and_key: tuple[x509.Certificate, rsa.RSAPrivateKey],
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Generate a client certificate signed by the test CA."""
    ca_cert, ca_key = ca_cert_and_key
    return _make_client_cert("FIELD-ALPHA", "FIELD_OPS", ca_cert, ca_key, serial=1001)


@pytest.fixture
def invalid_client_cert() -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Generate a self-signed certificate NOT signed by the test CA."""
    key = _make_key()
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "ROGUE-TERMINAL"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "UNKNOWN"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(seconds=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return key, cert


@pytest.fixture
def revoked_cert_and_crl(
    ca_cert_and_key: tuple[x509.Certificate, rsa.RSAPrivateKey],
    tmp_path: Path,
) -> tuple[x509.Certificate, Path]:
    """
    Create a client certificate and a CRL that revokes it.

    Returns:
        (revoked_cert, crl_pem_path)
    """
    ca_cert, ca_key = ca_cert_and_key
    _, revoked_cert = _make_client_cert("REVOKED-TERM", "FIELD_OPS", ca_cert, ca_key, serial=9999)

    now = datetime.datetime.now(datetime.timezone.utc)
    revoked = (
        x509.RevokedCertificateBuilder()
        .serial_number(revoked_cert.serial_number)
        .revocation_date(now)
        .build()
    )
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(now + datetime.timedelta(days=7))
        .add_revoked_certificate(revoked)
        .sign(ca_key, hashes.SHA256())
    )
    crl_path = tmp_path / "ca.crl"
    crl_path.write_bytes(crl.public_bytes(serialization.Encoding.PEM))
    return revoked_cert, crl_path
