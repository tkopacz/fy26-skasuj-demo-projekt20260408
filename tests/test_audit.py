"""Tests for the audit logging module."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from tactical_relay.audit import AuditLogger


class TestAuditLogEntry:
    """Tests for individual log entry format."""

    def test_entry_is_valid_json(self, audit_logger, tmp_path):
        log_path = str(tmp_path / "audit.jsonl")
        al = AuditLogger(log_path, hmac_secret="secret123")
        al.log(
            event=AuditLogger.EVENT_RECEIVED,
            message_id="msg-001",
            sender="FIELD-ALPHA",
            recipients=["HQ-PRIMARY"],
            classification="SECRET",
        )
        lines = Path(log_path).read_text().strip().splitlines()
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["event"] == "received"
        assert entry["message_id"] == "msg-001"

    def test_entry_contains_required_fields(self, tmp_path):
        log_path = str(tmp_path / "audit2.jsonl")
        al = AuditLogger(log_path, hmac_secret="secret123")
        al.log(
            event=AuditLogger.EVENT_QUEUED,
            message_id="msg-002",
            sender="FIELD-BRAVO",
            recipients=["HQ-PRIMARY"],
            classification="CONFIDENTIAL",
            routing_decision="direct",
            outcome="QUEUED",
        )
        entry = json.loads(Path(log_path).read_text().strip())
        required = {"timestamp", "event", "message_id", "sender", "recipients",
                    "classification", "routing_decision", "outcome", "prev_hmac", "this_hmac"}
        assert required.issubset(entry.keys())

    def test_message_content_not_logged(self, tmp_path):
        """Verify payload/content is never present in audit entries."""
        log_path = str(tmp_path / "audit3.jsonl")
        al = AuditLogger(log_path, hmac_secret="secret123")
        al.log(
            event=AuditLogger.EVENT_DELIVERED,
            message_id="msg-003",
            sender="FIELD-ALPHA",
            recipients=["HQ-PRIMARY"],
            classification="TOP_SECRET",
        )
        raw = Path(log_path).read_text()
        assert "payload" not in raw
        assert "content" not in raw

    def test_all_event_types_accepted(self, tmp_path):
        log_path = str(tmp_path / "audit_events.jsonl")
        al = AuditLogger(log_path, hmac_secret="secret123")
        for event in AuditLogger.VALID_EVENTS:
            al.log(
                event=event,
                message_id=f"msg-{event}",
                sender="FIELD-ALPHA",
                recipients=["HQ-PRIMARY"],
                classification="UNCLASSIFIED",
            )
        lines = Path(log_path).read_text().strip().splitlines()
        assert len(lines) == len(AuditLogger.VALID_EVENTS)

    def test_invalid_event_raises(self, tmp_path):
        log_path = str(tmp_path / "audit_invalid.jsonl")
        al = AuditLogger(log_path, hmac_secret="secret123")
        with pytest.raises(ValueError, match="Unknown audit event type"):
            al.log(
                event="INVALID_EVENT",
                message_id="msg-x",
                sender="S",
                recipients=["R"],
                classification="UNCLASSIFIED",
            )


class TestHmacChain:
    """Tests for HMAC chain integrity."""

    def test_chain_integrity_valid(self, tmp_path):
        log_path = str(tmp_path / "audit_chain.jsonl")
        al = AuditLogger(log_path, hmac_secret="secret-key")
        for i in range(5):
            al.log(
                event=AuditLogger.EVENT_RECEIVED,
                message_id=f"msg-{i}",
                sender="FIELD-ALPHA",
                recipients=["HQ-PRIMARY"],
                classification="UNCLASSIFIED",
            )
        assert AuditLogger.verify_chain(log_path, "secret-key") is True

    def test_tampered_entry_fails_verification(self, tmp_path):
        log_path = str(tmp_path / "audit_tampered.jsonl")
        al = AuditLogger(log_path, hmac_secret="secret-key")
        for i in range(3):
            al.log(
                event=AuditLogger.EVENT_RECEIVED,
                message_id=f"msg-{i}",
                sender="FIELD-ALPHA",
                recipients=["HQ-PRIMARY"],
                classification="UNCLASSIFIED",
            )
        # Tamper with the second line
        lines = Path(log_path).read_text().splitlines()
        entry = json.loads(lines[1])
        entry["sender"] = "TAMPERED-SENDER"
        lines[1] = json.dumps(entry)
        Path(log_path).write_text("\n".join(lines) + "\n")

        assert AuditLogger.verify_chain(log_path, "secret-key") is False

    def test_wrong_secret_fails_verification(self, tmp_path):
        log_path = str(tmp_path / "audit_wrongkey.jsonl")
        al = AuditLogger(log_path, hmac_secret="correct-key")
        al.log(
            event=AuditLogger.EVENT_RECEIVED,
            message_id="msg-0",
            sender="FIELD-ALPHA",
            recipients=["HQ-PRIMARY"],
            classification="UNCLASSIFIED",
        )
        assert AuditLogger.verify_chain(log_path, "wrong-key") is False

    def test_prev_hmac_links_entries(self, tmp_path):
        log_path = str(tmp_path / "audit_link.jsonl")
        al = AuditLogger(log_path, hmac_secret="secret-key")
        al.log(
            event=AuditLogger.EVENT_RECEIVED,
            message_id="msg-0",
            sender="FIELD-ALPHA",
            recipients=["HQ-PRIMARY"],
            classification="UNCLASSIFIED",
        )
        al.log(
            event=AuditLogger.EVENT_QUEUED,
            message_id="msg-0",
            sender="FIELD-ALPHA",
            recipients=["HQ-PRIMARY"],
            classification="UNCLASSIFIED",
        )
        lines = Path(log_path).read_text().strip().splitlines()
        entry0 = json.loads(lines[0])
        entry1 = json.loads(lines[1])
        assert entry1["prev_hmac"] == entry0["this_hmac"]

    def test_empty_secret_raises(self, tmp_path):
        log_path = str(tmp_path / "audit_nosecret.jsonl")
        with pytest.raises(ValueError, match="hmac_secret"):
            AuditLogger(log_path, hmac_secret="")

    def test_missing_file_returns_false(self):
        assert AuditLogger.verify_chain("/nonexistent/audit.jsonl", "key") is False


class TestEventCounts:
    """Tests for event counter aggregation."""

    def test_counts_accumulate(self, tmp_path):
        log_path = str(tmp_path / "audit_counts.jsonl")
        al = AuditLogger(log_path, hmac_secret="secret")
        al.log(AuditLogger.EVENT_RECEIVED, "m1", "S", ["R"], "U")
        al.log(AuditLogger.EVENT_RECEIVED, "m2", "S", ["R"], "U")
        al.log(AuditLogger.EVENT_REJECTED, "m3", "S", ["R"], "U")
        counts = al.get_counts()
        assert counts[AuditLogger.EVENT_RECEIVED] == 2
        assert counts[AuditLogger.EVENT_REJECTED] == 1
