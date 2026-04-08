"""
Integration tests for the full message pipeline.

Tests run auth → router → queue without establishing actual TLS connections.
Verifies end-to-end message flow and audit log integrity.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from cryptography.hazmat.primitives.serialization import Encoding

from tactical_relay.audit import AuditLogger
from tactical_relay.auth import AuthManager
from tactical_relay.messages_pb2 import TacticalMessage, DeliveryAck
from tactical_relay.queues import DLQ_RECIPIENT, QueueManager
from tactical_relay.router import RoutingEngine
from tactical_relay.transport import frame_message, parse_frame


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _build_message(
    message_id: str = "integ-001",
    sender: str = "FIELD-ALPHA",
    recipients: list[str] | None = None,
    priority: int = 5,
    classification: str = "UNCLASSIFIED",
    payload: bytes = b"test-payload",
    ttl_seconds: int = 0,
) -> TacticalMessage:
    """Build a TacticalMessage protobuf object."""
    msg = TacticalMessage()
    msg.message_id = message_id
    msg.sender = sender
    msg.recipients.extend(recipients or ["HQ-PRIMARY"])
    msg.priority = priority
    msg.classification = classification
    msg.payload = payload
    msg.timestamp = int(time.time())
    msg.ttl_seconds = ttl_seconds
    return msg


# ---------------------------------------------------------------------------
# Pipeline helper (simulates what TLSServer._process_message does)
# ---------------------------------------------------------------------------

def _run_pipeline(
    raw: bytes,
    auth: AuthManager,
    router: RoutingEngine,
    queues: QueueManager,
    audit: AuditLogger,
    client_ip: str = "127.0.0.1",
) -> str:
    """
    Execute the auth → routing → queue pipeline on a raw serialized message.

    Returns:
        Status string: "QUEUED", "REJECTED", or "PARSE_ERROR".
    """
    try:
        msg = TacticalMessage()
        msg.ParseFromString(raw)
    except Exception:
        return "PARSE_ERROR"

    if not msg.message_id or not msg.sender or not msg.recipients:
        audit.log(AuditLogger.EVENT_REJECTED, msg.message_id or "?", msg.sender or "?",
                  list(msg.recipients), msg.classification, outcome="INVALID_FIELDS")
        return "REJECTED"

    audit.log(AuditLogger.EVENT_RECEIVED, msg.message_id, msg.sender,
              list(msg.recipients), msg.classification)

    if not auth.validate_sender(msg.sender, ou=""):
        audit.log(AuditLogger.EVENT_REJECTED, msg.message_id, msg.sender,
                  list(msg.recipients), msg.classification, outcome="UNAUTHORIZED")
        return "REJECTED"

    audit.log(AuditLogger.EVENT_AUTHENTICATED, msg.message_id, msg.sender,
              list(msg.recipients), msg.classification)

    queue_names = router.route(
        message_id=msg.message_id,
        sender=msg.sender,
        priority=msg.priority or 5,
        classification=msg.classification or "UNCLASSIFIED",
        destination=msg.recipients[0] if msg.recipients else None,
    )
    audit.log(AuditLogger.EVENT_ROUTED, msg.message_id, msg.sender,
              list(msg.recipients), msg.classification, routing_decision=str(queue_names))

    queued_any = False
    for q in queue_names:
        ok = queues.enqueue(
            message_id=msg.message_id,
            recipient=q,
            priority=msg.priority or 5,
            classification=msg.classification or "UNCLASSIFIED",
            payload=raw,
            ttl_seconds=msg.ttl_seconds or 0,
        )
        if ok:
            queued_any = True
            audit.log(AuditLogger.EVENT_QUEUED, msg.message_id, msg.sender,
                      [q], msg.classification, outcome="QUEUED")

    return "QUEUED" if queued_any else "REJECTED"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestMessagePipeline:
    """Full pipeline integration tests."""

    def test_valid_message_lands_in_default_queue(
        self, auth_manager, routing_engine, queue_manager, audit_logger
    ):
        msg = _build_message(
            message_id="integ-001",
            sender="FIELD-ALPHA",
            classification="UNCLASSIFIED",
            priority=5,
        )
        raw = msg.SerializeToString()
        status = _run_pipeline(raw, auth_manager, routing_engine, queue_manager, audit_logger)
        assert status == "QUEUED"
        msg_out = queue_manager.dequeue("DEFAULT-QUEUE")
        assert msg_out is not None
        assert msg_out["message_id"] == "integ-001"

    def test_top_secret_field_message_goes_to_hq(
        self, auth_manager, routing_engine, queue_manager, audit_logger
    ):
        msg = _build_message(
            message_id="integ-002",
            sender="FIELD-BRAVO",
            classification="TOP_SECRET",
            priority=1,
        )
        raw = msg.SerializeToString()
        status = _run_pipeline(raw, auth_manager, routing_engine, queue_manager, audit_logger)
        assert status == "QUEUED"
        # Should be in both HQ queues (multicast)
        assert queue_manager.dequeue("HQ-PRIMARY") is not None
        assert queue_manager.dequeue("HQ-BACKUP") is not None

    def test_unauthorized_sender_rejected(
        self, auth_manager, routing_engine, queue_manager, audit_logger
    ):
        msg = _build_message(sender="ROGUE-TERMINAL")
        raw = msg.SerializeToString()
        status = _run_pipeline(raw, auth_manager, routing_engine, queue_manager, audit_logger)
        assert status == "REJECTED"
        # Nothing should be in any queue
        assert queue_manager.dequeue("DEFAULT-QUEUE") is None

    def test_invalid_message_bytes_parse_error(
        self, auth_manager, routing_engine, queue_manager, audit_logger
    ):
        status = _run_pipeline(b"not-protobuf-garbage", auth_manager, routing_engine,
                               queue_manager, audit_logger)
        assert status == "PARSE_ERROR"

    def test_confidential_routes_to_relay(
        self, auth_manager, routing_engine, queue_manager, audit_logger
    ):
        msg = _build_message(
            message_id="integ-conf-001",
            sender="FIELD-ALPHA",
            classification="CONFIDENTIAL",
            priority=5,
        )
        raw = msg.SerializeToString()
        status = _run_pipeline(raw, auth_manager, routing_engine, queue_manager, audit_logger)
        assert status == "QUEUED"
        assert queue_manager.dequeue("RELAY-NODE-1") is not None


class TestAuditChainAfterPipeline:
    """Verify audit log HMAC chain integrity after processing messages."""

    def test_chain_intact_after_multiple_messages(
        self, tmp_path, auth_manager, routing_engine, queue_manager
    ):
        log_path = str(tmp_path / "integ_audit.jsonl")
        audit = AuditLogger(log_path, hmac_secret="integ-test-secret")

        for i in range(5):
            msg = _build_message(
                message_id=f"chain-msg-{i}",
                sender="FIELD-ALPHA",
                classification="UNCLASSIFIED",
                priority=5,
            )
            _run_pipeline(msg.SerializeToString(), auth_manager, routing_engine, queue_manager, audit)

        assert AuditLogger.verify_chain(log_path, "integ-test-secret") is True


class TestMessageSerialization:
    """Tests for protobuf message serialization round-trip."""

    def test_tactical_message_round_trip(self):
        msg = _build_message(
            message_id="serial-001",
            sender="FIELD-ALPHA",
            recipients=["HQ-PRIMARY", "HQ-BACKUP"],
            priority=3,
            classification="SECRET",
            payload=b"\x00\x01\x02encrypted-blob",
            ttl_seconds=300,
        )
        raw = msg.SerializeToString()
        assert len(raw) > 0

        restored = TacticalMessage()
        restored.ParseFromString(raw)
        assert restored.message_id == "serial-001"
        assert restored.sender == "FIELD-ALPHA"
        assert list(restored.recipients) == ["HQ-PRIMARY", "HQ-BACKUP"]
        assert restored.priority == 3
        assert restored.classification == "SECRET"
        assert restored.payload == b"\x00\x01\x02encrypted-blob"
        assert restored.ttl_seconds == 300

    def test_delivery_ack_round_trip(self):
        ack = DeliveryAck()
        ack.message_id = "ack-001"
        ack.recipient = "HQ-PRIMARY"
        ack.status = "QUEUED"
        ack.timestamp = int(time.time())

        raw = ack.SerializeToString()
        restored = DeliveryAck()
        restored.ParseFromString(raw)

        assert restored.message_id == "ack-001"
        assert restored.recipient == "HQ-PRIMARY"
        assert restored.status == "QUEUED"

    def test_framing_with_real_message(self):
        msg = _build_message()
        raw = msg.SerializeToString()
        framed = frame_message(raw)
        length, payload = parse_frame(framed)
        assert length == len(raw)
        assert payload == raw
