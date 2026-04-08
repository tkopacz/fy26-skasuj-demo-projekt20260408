# Security Policy

## Threat Model

The tactical relay service operates in a network environment where all participants are assumed to hold valid X.509 certificates issued by a trusted CA. The following threats are addressed:

| Threat | Mitigation |
|--------|-----------|
| Unauthenticated access | mTLS required — connections without a valid client certificate are rejected at the TLS handshake |
| Message injection from unauthorized senders | CN/role validation against SQLite authorization database |
| Revoked terminal access | CRL checked per-connection against a locally cached CRL file |
| Audit log tampering | HMAC-SHA256 chain — each entry covers the previous entry's HMAC |
| Message content exposure in logs | Audit log records metadata only; payload bytes are never written |
| Denial of service (rate) | Per-IP sliding window rate limiter |
| Denial of service (connections) | Configurable maximum concurrent connection limit |
| Large message attacks | Hard-coded 10 MB cap on framed message length |
| Queue exhaustion | Configurable `max_depth_per_queue`; excess messages rejected |
| Privilege escalation | Service runs as non-root user `relay` with hardened systemd unit |

---

## Trust Boundaries

```
[External Network]
      │  mTLS (mutual TLS 1.2+)
      ▼
[TLS Listener: 0.0.0.0:8443]
      │  Verified client certificate
      ▼
[AuthManager]  ──→  SQLite auth DB (local filesystem)
      │              CRL file (local filesystem)
      ▼
[RoutingEngine]  ──→  YAML rules file (read-only at startup)
      │
      ▼
[QueueManager]  ──→  SQLite queue DB (local filesystem)
      │
      ▼
[AuditLogger]  ──→  Rotating JSONL file (HMAC chain)

[Health Endpoint: 127.0.0.1:8080]  ← localhost only
```

External clients cross the TLS boundary. All other communication is local (filesystem, loopback).

---

## mTLS Trust Chain

1. The service loads the CA bundle from `certs/ca.crt`.
2. `ssl.CERT_REQUIRED` is set — the TLS handshake fails if the client does not present a certificate signed by the CA.
3. After the handshake, the server extracts the CN and OU from the client certificate's subject.
4. The CN is looked up in the authorization database. Only active records are accepted.
5. The CRL is consulted to reject revoked certificates.

**Certificate validation is performed by OpenSSL via Python's `ssl` module.** The service does not implement its own certificate chain verification — it relies on the operating system's TLS stack.

---

## Key Management Procedures

### Private Keys

- Server private key (`server.key`) must be readable only by the `relay` user: `chmod 400`.
- CA private key must be stored off-system and used only to sign new certificates.
- Client private keys are held by the respective terminal — never by this service.

### HMAC Secret

- The audit HMAC secret (`RELAY_AUDIT_HMAC_SECRET`) must be a cryptographically random string of at least 256 bits (32 bytes hex-encoded = 64 chars).
- It must be stored in the secrets environment file (`/etc/tactical-relay/secrets.env`) with `chmod 600`, readable only by root.
- Never hard-code it or commit it to version control.
- Generate: `openssl rand -hex 32`

---

## Certificate Rotation

1. Generate a new key and CSR for the server or client.
2. Have the CA sign the CSR.
3. Replace the certificate file and restart the service (or send SIGTERM for graceful restart).
4. Update the authorization database if the CN changes.
5. Issue a new CRL if you need to revoke the old certificate.

---

## Audit Log Integrity

Each JSONL entry contains:
- `prev_hmac`: The HMAC of the previous entry (genesis = `000...0`).
- `this_hmac`: HMAC-SHA256 over the JSON serialization of the entry (excluding `this_hmac`).

To verify:

```bash
python3 -c "
from tactical_relay.audit import AuditLogger
import os, sys
ok = AuditLogger.verify_chain(sys.argv[1], os.environ['RELAY_AUDIT_HMAC_SECRET'])
sys.exit(0 if ok else 1)
" logs/audit.jsonl
```

**Any modification to a historical entry will cause verification to fail for all subsequent entries.**

---

## Known Limitations

1. **CRL is cached on disk** — the service does not automatically fetch updated CRLs from an OCSP responder or CDP. Operators must update the CRL file and restart the service.
2. **SQLite concurrency** — the service uses a single SQLite connection. For very high throughput, consider migrating to PostgreSQL.
3. **No message encryption at rest** — the `payload` field in the queue database is stored as raw bytes. If the payload is sensitive, it should be encrypted by the sender before transmission.
4. **No replay protection** — the service does not detect duplicate `message_id` values. Senders should ensure uniqueness (e.g., UUID v4).
5. **Single-node deployment** — there is no built-in clustering or high-availability. For HA, operate multiple instances behind a load balancer with a shared database.

---

## Reporting Security Issues

To report a security vulnerability, contact the security team directly. Do not open a public issue.
