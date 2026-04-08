"""
Audit logging with HMAC chain integrity for the tactical relay service.

Each log entry is a JSON object that includes the HMAC of the previous entry,
forming a tamper-evident chain. Message content is never logged.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import logging.handlers
import os
import threading
import time
from pathlib import Path
from typing import ClassVar, Optional


class AuditLogger:
    """
    Structured, HMAC-chained audit logger.

    Each entry records metadata about message lifecycle events. A chain of
    HMACs is maintained so any tampering with a historical entry is detectable.

    Thread-safe: internal lock serialises all writes.
    """

    # Valid event types
    EVENT_RECEIVED: ClassVar[str] = "received"
    EVENT_AUTHENTICATED: ClassVar[str] = "authenticated"
    EVENT_ROUTED: ClassVar[str] = "routed"
    EVENT_QUEUED: ClassVar[str] = "queued"
    EVENT_DELIVERED: ClassVar[str] = "delivered"
    EVENT_EXPIRED: ClassVar[str] = "expired"
    EVENT_REJECTED: ClassVar[str] = "rejected"

    VALID_EVENTS: ClassVar[frozenset[str]] = frozenset(
        {
            EVENT_RECEIVED,
            EVENT_AUTHENTICATED,
            EVENT_ROUTED,
            EVENT_QUEUED,
            EVENT_DELIVERED,
            EVENT_EXPIRED,
            EVENT_REJECTED,
        }
    )

    def __init__(
        self,
        log_path: str,
        hmac_secret: str,
        max_bytes: int = 100 * 1024 * 1024,
        backup_count: int = 10,
    ) -> None:
        """
        Initialise the AuditLogger.

        Args:
            log_path: Filesystem path to the audit log file.
            hmac_secret: Secret key for HMAC computation. Must not be empty.
            max_bytes: Maximum file size before rotation.
            backup_count: Number of rotated backup files to retain.

        Raises:
            ValueError: If hmac_secret is empty.
        """
        if not hmac_secret:
            raise ValueError("audit.hmac_secret must not be empty")

        self._secret = hmac_secret.encode() if isinstance(hmac_secret, str) else hmac_secret
        self._lock = threading.Lock()
        self._prev_hmac: str = "0" * 64  # genesis sentinel

        # Ensure the log directory exists
        Path(log_path).parent.mkdir(parents=True, exist_ok=True)

        self._handler = logging.handlers.RotatingFileHandler(
            log_path,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        self._logger = logging.getLogger(f"audit.{os.path.basename(log_path)}")
        self._logger.setLevel(logging.DEBUG)
        self._logger.propagate = False
        if not self._logger.handlers:
            self._logger.addHandler(self._handler)

        # Replay existing chain tail so we can continue appending correctly
        self._prev_hmac = self._read_last_hmac(log_path)

        # Stats counters
        self._counts: dict[str, int] = {ev: 0 for ev in self.VALID_EVENTS}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def log(
        self,
        event: str,
        message_id: str,
        sender: str,
        recipients: list[str],
        classification: str,
        routing_decision: Optional[str] = None,
        outcome: Optional[str] = None,
        extra: Optional[dict] = None,
    ) -> None:
        """
        Write a structured audit log entry.

        Args:
            event: One of the EVENT_* constants.
            message_id: Unique message identifier (metadata only).
            sender: CN of the originating terminal.
            recipients: List of intended recipient CNs.
            classification: Message classification level.
            routing_decision: Human-readable routing outcome.
            outcome: Final disposition (e.g. DELIVERED, REJECTED).
            extra: Optional additional metadata (no message content).

        Raises:
            ValueError: If event is not a recognised event type.
        """
        if event not in self.VALID_EVENTS:
            raise ValueError(f"Unknown audit event type: {event!r}")

        with self._lock:
            entry = {
                "timestamp": time.time(),
                "event": event,
                "message_id": message_id,
                "sender": sender,
                "recipients": recipients,
                "classification": classification,
                "routing_decision": routing_decision,
                "outcome": outcome,
                "extra": extra or {},
                "prev_hmac": self._prev_hmac,
            }
            this_hmac = self._compute_hmac(entry)
            entry["this_hmac"] = this_hmac
            self._logger.info(json.dumps(entry, separators=(",", ":")))
            self._prev_hmac = this_hmac
            self._counts[event] = self._counts.get(event, 0) + 1

    def get_counts(self) -> dict[str, int]:
        """Return a snapshot of per-event counts."""
        with self._lock:
            return dict(self._counts)

    @classmethod
    def verify_chain(cls, log_file_path: str, hmac_secret: str) -> bool:
        """
        Verify the HMAC chain integrity of an audit log file.

        Reads every line of the log file and re-computes the HMAC chain,
        returning True only if every entry is valid and unmodified.

        Args:
            log_file_path: Path to the audit log file to verify.
            hmac_secret: The HMAC secret used when the log was written.

        Returns:
            True if the chain is intact, False if any tampering is detected.
        """
        secret = hmac_secret.encode() if isinstance(hmac_secret, str) else hmac_secret
        prev_hmac = "0" * 64

        try:
            with open(log_file_path, "r", encoding="utf-8") as fh:
                for lineno, line in enumerate(fh, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        logging.error("Audit chain verify: bad JSON at line %d", lineno)
                        return False

                    stored_hmac = entry.pop("this_hmac", None)
                    if stored_hmac is None:
                        logging.error("Audit chain verify: missing this_hmac at line %d", lineno)
                        return False

                    if entry.get("prev_hmac") != prev_hmac:
                        logging.error(
                            "Audit chain verify: prev_hmac mismatch at line %d", lineno
                        )
                        return False

                    expected = cls._compute_hmac_static(entry, secret)
                    if not hmac.compare_digest(expected, stored_hmac):
                        logging.error(
                            "Audit chain verify: HMAC mismatch at line %d", lineno
                        )
                        return False

                    prev_hmac = stored_hmac
        except FileNotFoundError:
            logging.error("Audit chain verify: file not found: %s", log_file_path)
            return False

        return True

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _compute_hmac(self, entry: dict) -> str:
        """Compute HMAC-SHA256 over the serialised entry (excluding this_hmac)."""
        return self._compute_hmac_static(entry, self._secret)

    @staticmethod
    def _compute_hmac_static(entry: dict, secret: bytes) -> str:
        """Static version for use in verify_chain."""
        serialised = json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()
        return hmac.new(secret, serialised, hashlib.sha256).hexdigest()

    @staticmethod
    def _read_last_hmac(log_path: str) -> str:
        """Read the this_hmac of the last entry in an existing log file."""
        sentinel = "0" * 64
        try:
            with open(log_path, "rb") as fh:
                # Seek to find the last non-empty line efficiently
                fh.seek(0, 2)
                size = fh.tell()
                if size == 0:
                    return sentinel
                # Read the last 4 KB which should contain at least one entry
                fh.seek(max(0, size - 4096))
                tail = fh.read().decode("utf-8", errors="replace")
                lines = [l.strip() for l in tail.splitlines() if l.strip()]
                if not lines:
                    return sentinel
                last = json.loads(lines[-1])
                return last.get("this_hmac", sentinel)
        except (FileNotFoundError, json.JSONDecodeError, KeyError):
            return sentinel
