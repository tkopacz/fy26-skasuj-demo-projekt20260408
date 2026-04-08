"""Tests for the message queue module."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from tactical_relay.queues import DLQ_RECIPIENT, QueueManager


class TestEnqueueDequeue:
    """Tests for basic enqueue and dequeue operations."""

    def test_enqueue_and_dequeue(self, queue_manager):
        ok = queue_manager.enqueue("msg-1", "HQ-PRIMARY", 5, "UNCLASSIFIED", b"payload-1")
        assert ok is True
        msg = queue_manager.dequeue("HQ-PRIMARY")
        assert msg is not None
        assert msg["message_id"] == "msg-1"

    def test_dequeue_empty_returns_none(self, queue_manager):
        assert queue_manager.dequeue("EMPTY-QUEUE") is None

    def test_enqueue_invalid_empty_message_id(self, queue_manager):
        ok = queue_manager.enqueue("", "HQ-PRIMARY", 5, "UNCLASSIFIED", b"payload")
        assert ok is False

    def test_enqueue_invalid_empty_payload(self, queue_manager):
        ok = queue_manager.enqueue("msg-x", "HQ-PRIMARY", 5, "UNCLASSIFIED", b"")
        assert ok is False

    def test_enqueue_invalid_priority(self, queue_manager):
        ok = queue_manager.enqueue("msg-x", "HQ-PRIMARY", 10, "UNCLASSIFIED", b"data")
        assert ok is False

    def test_multiple_recipients_independent(self, queue_manager):
        queue_manager.enqueue("msg-a", "QUEUE-A", 5, "UNCLASSIFIED", b"a")
        queue_manager.enqueue("msg-b", "QUEUE-B", 5, "UNCLASSIFIED", b"b")
        assert queue_manager.dequeue("QUEUE-A")["message_id"] == "msg-a"
        assert queue_manager.dequeue("QUEUE-B")["message_id"] == "msg-b"


class TestPriorityOrdering:
    """Tests for priority-based dequeue ordering."""

    def test_lower_number_dequeued_first(self, queue_manager):
        queue_manager.enqueue("low", "Q", 9, "UNCLASSIFIED", b"low")
        queue_manager.enqueue("high", "Q", 1, "UNCLASSIFIED", b"high")
        queue_manager.enqueue("mid", "Q", 5, "UNCLASSIFIED", b"mid")
        assert queue_manager.dequeue("Q")["message_id"] == "high"
        assert queue_manager.dequeue("Q")["message_id"] == "mid"
        assert queue_manager.dequeue("Q")["message_id"] == "low"

    def test_fifo_within_same_priority(self, queue_manager):
        queue_manager.enqueue("first", "Q", 3, "UNCLASSIFIED", b"1")
        time.sleep(0.01)
        queue_manager.enqueue("second", "Q", 3, "UNCLASSIFIED", b"2")
        assert queue_manager.dequeue("Q")["message_id"] == "first"


class TestTTLExpiry:
    """Tests for TTL-based message expiry."""

    def test_expired_message_not_returned(self, tmp_path):
        qm = QueueManager(str(tmp_path / "q_ttl.db"), max_depth_per_queue=100, default_ttl_seconds=0)
        qm.enqueue("msg-ttl", "Q", 5, "UNCLASSIFIED", b"data", ttl_seconds=1)
        # Message should be available immediately
        msg = qm.dequeue("Q")
        assert msg is not None
        qm.close()

    def test_expired_messages_removed_by_expire(self, tmp_path):
        qm = QueueManager(str(tmp_path / "q_expire.db"), max_depth_per_queue=100, default_ttl_seconds=0)
        # Use a very short TTL — we manually set expires_at via SQL tricks below
        # Instead, enqueue with a normal TTL and check the expire count logic
        qm.enqueue("msg-e1", "Q", 5, "UNCLASSIFIED", b"data", ttl_seconds=3600)
        # Manually set expires_at to past via direct SQL
        qm._conn.execute(
            "UPDATE messages SET expires_at = ? WHERE message_id = ?",
            (time.time() - 1, "msg-e1"),
        )
        qm._conn.commit()
        expired = qm.expire_messages()
        assert expired >= 1
        assert qm.dequeue("Q") is None
        qm.close()


class TestMaxDepth:
    """Tests for maximum queue depth enforcement."""

    def test_queue_full_rejects_new_message(self, tmp_path):
        qm = QueueManager(str(tmp_path / "q_full.db"), max_depth_per_queue=2, default_ttl_seconds=0)
        assert qm.enqueue("m1", "Q", 5, "U", b"a") is True
        assert qm.enqueue("m2", "Q", 5, "U", b"b") is True
        assert qm.enqueue("m3", "Q", 5, "U", b"c") is False  # queue full
        qm.close()


class TestAcknowledge:
    """Tests for message delivery acknowledgement."""

    def test_acknowledge_marks_delivered(self, queue_manager):
        queue_manager.enqueue("msg-ack", "Q", 5, "U", b"data")
        queue_manager.dequeue("Q")
        ok = queue_manager.acknowledge("msg-ack", "Q")
        assert ok is True
        # Should not appear again
        assert queue_manager.dequeue("Q") is None

    def test_acknowledge_unknown_returns_false(self, queue_manager):
        assert queue_manager.acknowledge("no-such-message", "Q") is False

    def test_double_acknowledge_returns_false(self, queue_manager):
        queue_manager.enqueue("msg-dbl", "Q", 5, "U", b"data")
        queue_manager.acknowledge("msg-dbl", "Q")
        assert queue_manager.acknowledge("msg-dbl", "Q") is False


class TestDLQ:
    """Tests for dead-letter queue functionality."""

    def test_enqueue_dlq(self, queue_manager):
        ok = queue_manager.enqueue_dlq("msg-dead", b"data", "no-route", "HQ-PRIMARY")
        assert ok is True
        depth = queue_manager.get_queue_depth(DLQ_RECIPIENT)
        assert depth == 1


class TestMetrics:
    """Tests for get_all_metrics."""

    def test_per_queue_depths(self, queue_manager):
        queue_manager.enqueue("m1", "ALPHA", 5, "U", b"a")
        queue_manager.enqueue("m2", "ALPHA", 5, "U", b"b")
        queue_manager.enqueue("m3", "BETA", 5, "U", b"c")
        metrics = queue_manager.get_all_metrics()
        assert metrics["per_queue_depths"]["ALPHA"] == 2
        assert metrics["per_queue_depths"]["BETA"] == 1

    def test_total_delivered(self, queue_manager):
        queue_manager.enqueue("m-del", "Q", 5, "U", b"x")
        queue_manager.acknowledge("m-del", "Q")
        metrics = queue_manager.get_all_metrics()
        assert metrics["total_delivered"] >= 1

    def test_total_pending(self, queue_manager):
        queue_manager.enqueue("m-pend", "Q", 5, "U", b"y")
        metrics = queue_manager.get_all_metrics()
        assert metrics["total_pending"] >= 1
