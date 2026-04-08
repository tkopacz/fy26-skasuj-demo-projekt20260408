# Tactical Message Relay Service

A production-grade secure tactical message relay service written in Python. Messages are relayed between field terminals and command nodes using mutual TLS (mTLS), priority queuing, rule-based routing, and HMAC-chained audit logging.

---

## Architecture Overview

```
Field Terminal ──mTLS──► TLSServer ──► AuthManager ──► RoutingEngine ──► QueueManager
                                            │                                  │
                                       AuditLogger ◄──────────────────────────┘
                                            │
                                      RotatingFileHandler (HMAC chain)

HealthServer (localhost only) ◄── aiohttp ──► /health, /metrics
```

### Components

| Module | Responsibility |
|--------|----------------|
| `transport.py` | Async mTLS server, 4-byte length-prefix framing, rate limiting |
| `auth.py` | X.509 identity extraction, CRL revocation check, SQLite authorization |
| `queues.py` | Priority queues with TTL, DLQ, and SQLite persistence (WAL mode) |
| `router.py` | YAML-driven rule engine: priority, classification, fnmatch patterns |
| `audit.py` | HMAC-chained structured JSONL audit log (metadata only, no content) |
| `health.py` | aiohttp health (`/health`) and Prometheus metrics (`/metrics`) |
| `config.py` | YAML + env-var config with full validation |
| `messages_pb2.py` | Protobuf message classes (TacticalMessage, DeliveryAck) |

---

## Quick Start with Docker

### 1. Set the audit HMAC secret

```bash
export RELAY_AUDIT_HMAC_SECRET="$(openssl rand -hex 32)"
```

### 2. Start the service

```bash
docker compose up --build
```

### 3. Check health

```bash
curl http://127.0.0.1:8080/health
curl http://127.0.0.1:8080/metrics
```

---

## Deployment — Bare Metal

### Prerequisites

- Python 3.11+
- openssl

### 1. Create system user and directories

```bash
useradd --system --home /opt/tactical-relay --shell /usr/sbin/nologin relay
mkdir -p /opt/tactical-relay /etc/tactical-relay /var/lib/tactical-relay /var/log/tactical-relay
chown relay:relay /opt/tactical-relay /var/lib/tactical-relay /var/log/tactical-relay
```

### 2. Install the package

```bash
cd /opt/tactical-relay
python3.11 -m venv venv
venv/bin/pip install tactical-relay
```

### 3. Generate certificates

```bash
bash scripts/generate_certs.sh /etc/tactical-relay/certs
```

### 4. Set secrets

```bash
cat > /etc/tactical-relay/secrets.env <<EOF
RELAY_AUDIT_HMAC_SECRET=$(openssl rand -hex 32)
EOF
chmod 600 /etc/tactical-relay/secrets.env
chown root:root /etc/tactical-relay/secrets.env
```

### 5. Install systemd unit

```bash
cp tactical-relay.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now tactical-relay
```

---

## Configuration Reference

All settings can be overridden via environment variables with the `RELAY_` prefix.

| Setting | Env var | Default | Description |
|---------|---------|---------|-------------|
| `transport.port` | `RELAY_TRANSPORT_PORT` | `8443` | mTLS port |
| `transport.certfile` | `RELAY_TRANSPORT_CERTFILE` | `certs/server.crt` | Server certificate |
| `transport.keyfile` | `RELAY_TRANSPORT_KEYFILE` | `certs/server.key` | Server private key |
| `transport.ca_bundle` | `RELAY_TRANSPORT_CA_BUNDLE` | `certs/ca.crt` | CA bundle for client verification |
| `transport.rate_limit_per_ip` | `RELAY_TRANSPORT_RATE_LIMIT_PER_IP` | `100` | Max messages/second/IP |
| `transport.max_connections` | `RELAY_TRANSPORT_MAX_CONNECTIONS` | `1000` | Max concurrent connections |
| `auth.db_path` | `RELAY_AUTH_DB_PATH` | `data/auth.db` | Authorization SQLite DB |
| `auth.crl_path` | `RELAY_AUTH_CRL_PATH` | `certs/ca.crl` | Certificate revocation list |
| `queues.max_depth_per_queue` | `RELAY_QUEUES_MAX_DEPTH_PER_QUEUE` | `10000` | Max messages per queue |
| `queues.default_ttl_seconds` | `RELAY_QUEUES_DEFAULT_TTL_SECONDS` | `3600` | Default message TTL |
| `audit.log_path` | `RELAY_AUDIT_LOG_PATH` | `logs/audit.jsonl` | Audit log file |
| `audit.hmac_secret` | `RELAY_AUDIT_HMAC_SECRET` | *(required)* | HMAC secret for audit chain |
| `health.port` | `RELAY_HEALTH_PORT` | `8080` | Health endpoint port |
| `routing.rules_file` | `RELAY_ROUTING_RULES_FILE` | `config/routing_rules.yaml` | Routing rules |
| `log_level` | `RELAY_LOG_LEVEL` | `INFO` | Python log level |

---

## Certificate Setup Guide

### Test environment

```bash
bash scripts/generate_certs.sh certs/
```

### Production

1. Obtain CA certificate from your PKI team.
2. Generate server key and submit CSR for signing.
3. Generate client keys and CSRs for each terminal.
4. Obtain CRL and configure refresh.
5. Never store private keys in version control.

---

## Routing Rules

Rules defined in `config/routing_rules.yaml`:

```yaml
rules:
  - name: "urgent-field"
    match:
      priority_max: 2
      classification: "TOP_SECRET"
      originator_pattern: "FIELD-*"
    action:
      type: "multicast"
      recipients: ["HQ-PRIMARY", "HQ-BACKUP"]

  - name: "default"
    match: {}
    action:
      type: "direct"
      recipients: ["DEFAULT-QUEUE"]
```

---

## Operations

### Verify audit log integrity

```bash
python3 -c "
from tactical_relay.audit import AuditLogger
import os
ok = AuditLogger.verify_chain('logs/audit.jsonl', os.environ['RELAY_AUDIT_HMAC_SECRET'])
print('Chain intact:', ok)
"
```

### Running Tests

```bash
pip install -e ".[dev]"
export RELAY_AUDIT_HMAC_SECRET=test-secret
pytest tests/ -v
```