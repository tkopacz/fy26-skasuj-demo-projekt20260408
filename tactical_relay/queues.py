"""
Persistent message queue backed by SQLite in WAL mode.

Supports per-recipient priority queues with TTL, delivery acknowledgement,
configurable maximum depth, and a dead-letter queue.
"""

from __future__ import annotations

import logging
import sqlite3
import time
from typing import Optional

logger = logging.getLogger(__name__)

# Special recipient name used for dead-letter queue
DLQ_RECIPIENT = "__dlq__"

_SCHEMA_SQL = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS messages (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id      TEXT    NOT NULL,
    recipient       TEXT    NOT NULL,
    priority        INTEGER NOT NULL DEFAULT 5,
    classification  TEXT    NOT NULL DEFAULT 'UNCLASSIFIED',
    payload         BLOB    NOT NULL,
    queued_at       REAL    NOT NULL,
    expires_at      REAL,
    in_flight       INTEGER NOT NULL DEFAULT 0,
    delivered       INTEGER NOT NULL DEFAULT 0,
    delivered_at    REAL
);

CREATE INDEX IF NOT EXISTS idx_messages_recipient
    ON messages (recipient, delivered, in_flight, priority, queued_at);
CREATE INDEX IF NOT EXISTS idx_messages_expires
    ON messages (expires_at, delivered);
"""


class QueueManager:
    """
    SQLite-backed message queue manager with TTL, priority, and DLQ support.

    All database operations are serialised via SQLite's WAL mode which allows
    concurrent reads while writes are exclusive. Uses a single connection with
    ``check_same_thread=False``; callers are responsible for thread safety at
    the application level.
    """

    def __init__(
        self,
        db_path: str,
        max_depth_per_queue: int = 10_000,
        default_ttl_seconds: int = 3600,
    ) -> None:
        """
        Initialise the QueueManager.

        Args:
            db_path: Filesystem path to the SQLite database.
            max_depth_per_queue: Reject enqueue when recipient queue exceeds this.
            default_ttl_seconds: Default TTL when ttl_seconds=0 is supplied (0 means
                                 no expiry when the global default is also 0).
        """
        self._db_path = db_path
        self._max_depth = max_depth_per_queue
        self._default_ttl = default_ttl_seconds
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_schema(self) -> None:
        """Create the database schema if it does not exist."""
        with self._conn:
            self._conn.executescript(_SCHEMA_SQL)

    # ------------------------------------------------------------------
    # Core queue operations
    # ------------------------------------------------------------------

    def enqueue(
        self,
        message_id: str,
        recipient: str,
        priority: int,
        classification: str,
        payload: bytes,
        ttl_seconds: int = 0,
    ) -> bool:
        """
        Add a message to a recipient's queue.

        Args:
            message_id: Unique message identifier.
            recipient: Destination queue name.
            priority: Message priority (1 = highest, 9 = lowest).
            classification: Security classification label.
            payload: Serialised message bytes.
            ttl_seconds: Seconds until the message expires. 0 uses the service
                         default; use a negative value to disable expiry entirely.

        Returns:
            True on success, False if the queue is full or input is invalid.
        """
        if not message_id or not recipient or not payload:
            logger.warning("enqueue: invalid arguments (message_id=%r, recipient=%r)", message_id, recipient)
            return False

        if priority < 1 or priority > 9:
            logger.warning("enqueue: priority %d out of range 1-9 for message %r", priority, message_id)
            return False

        # Check queue depth (include in-flight to enforce limit)
        depth = self.get_queue_depth(recipient)
        if depth >= self._max_depth:
            logger.warning(
                "enqueue: queue for %r is full (%d/%d), rejecting %r",
                recipient, depth, self._max_depth, message_id,
            )
            return False

        now = time.time()
        effective_ttl = ttl_seconds if ttl_seconds != 0 else self._default_ttl
        expires_at = (now + effective_ttl) if effective_ttl > 0 else None

        with self._conn:
            self._conn.execute(
                """
                INSERT INTO messages
                    (message_id, recipient, priority, classification, payload,
                     queued_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (message_id, recipient, priority, classification, payload, now, expires_at),
            )
        logger.debug("enqueue: queued message_id=%r for recipient=%r (priority=%d)", message_id, recipient, priority)
        return True

    def dequeue(self, recipient: str) -> Optional[dict]:
        """
        Return the highest-priority non-expired message for a recipient.

        Priority ordering: lower number = higher priority. Ties broken by
        earliest queued_at.

        Args:
            recipient: The recipient queue to pop from.

        Returns:
            A dict with message fields, or None if the queue is empty or all
            remaining messages are expired.
        """
        self.expire_messages()
        now = time.time()
        # Find and atomically mark the highest-priority message as in-flight
        with self._conn:
            cursor = self._conn.execute(
                """
                SELECT id, message_id, recipient, priority, classification, payload, queued_at, expires_at
                FROM messages
                WHERE recipient = ?
                  AND delivered = 0
                  AND in_flight = 0
                  AND (expires_at IS NULL OR expires_at > ?)
                ORDER BY priority ASC, queued_at ASC
                LIMIT 1
                """,
                (recipient, now),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            # Mark as in-flight so it won't be returned again until acknowledged
            self._conn.execute(
                "UPDATE messages SET in_flight = 1 WHERE id = ?",
                (row["id"],),
            )
        return dict(row)

    def acknowledge(self, message_id: str, recipient: str) -> bool:
        """
        Mark a message as successfully delivered.

        Args:
            message_id: The message to acknowledge.
            recipient: The recipient who received it.

        Returns:
            True if the row was found and updated, False otherwise.
        """
        now = time.time()
        with self._conn:
            cur = self._conn.execute(
                """
                UPDATE messages
                SET delivered = 1, delivered_at = ?, in_flight = 0
                WHERE message_id = ? AND recipient = ? AND delivered = 0
                """,
                (now, message_id, recipient),
            )
        if cur.rowcount > 0:
            logger.debug("acknowledge: message_id=%r delivered to recipient=%r", message_id, recipient)
            return True
        logger.warning("acknowledge: message_id=%r not found for recipient=%r", message_id, recipient)
        return False

    def expire_messages(self) -> int:
        """
        Mark all TTL-exceeded messages as delivered (to the DLQ).

        Returns:
            Number of messages expired.
        """
        now = time.time()
        with self._conn:
            cur = self._conn.execute(
                """
                UPDATE messages
                SET delivered = 1, delivered_at = ?, recipient = '__dlq__' || '_expired_' || recipient
                WHERE delivered = 0
                  AND expires_at IS NOT NULL
                  AND expires_at <= ?
                """,
                (now, now),
            )
        if cur.rowcount:
            logger.info("expire_messages: expired %d messages", cur.rowcount)
        return cur.rowcount

    def enqueue_dlq(
        self,
        message_id: str,
        payload: bytes,
        reason: str,
        original_recipient: str,
    ) -> bool:
        """
        Send a message to the dead-letter queue.

        Args:
            message_id: Original message identifier.
            payload: Serialised message bytes.
            reason: Human-readable rejection reason.
            original_recipient: The originally intended recipient.

        Returns:
            True on success.
        """
        logger.warning(
            "DLQ: message_id=%r original_recipient=%r reason=%r",
            message_id, original_recipient, reason,
        )
        return self.enqueue(
            message_id=message_id,
            recipient=DLQ_RECIPIENT,
            priority=9,
            classification="UNCLASSIFIED",
            payload=payload,
            ttl_seconds=-1,  # DLQ messages never expire automatically
        )

    # ------------------------------------------------------------------
    # Metrics / introspection
    # ------------------------------------------------------------------

    def get_queue_depth(self, recipient: str) -> int:
        """
        Return the number of undelivered, non-expired messages for a recipient.

        Args:
            recipient: Queue name to check.

        Returns:
            Current queue depth.
        """
        now = time.time()
        cursor = self._conn.execute(
            """
            SELECT COUNT(*) FROM messages
            WHERE recipient = ?
              AND delivered = 0
              AND (expires_at IS NULL OR expires_at > ?)
            """,
            (recipient, now),
        )
        return cursor.fetchone()[0]

    def get_all_metrics(self) -> dict:
        """
        Return aggregated metrics across all queues.

        Returns:
            A dict with keys:
            - per_queue_depths: dict mapping recipient → depth
            - total_delivered: int
            - total_expired: int
            - total_pending: int
        """
        now = time.time()

        # Per-queue pending depths
        cursor = self._conn.execute(
            """
            SELECT recipient, COUNT(*) as cnt
            FROM messages
            WHERE delivered = 0
              AND (expires_at IS NULL OR expires_at > ?)
            GROUP BY recipient
            """,
            (now,),
        )
        per_queue = {row["recipient"]: row["cnt"] for row in cursor.fetchall()}

        # Delivered count
        cur2 = self._conn.execute(
            "SELECT COUNT(*) FROM messages WHERE delivered = 1"
        )
        total_delivered = cur2.fetchone()[0]

        # Expired count (messages whose expires_at has passed, whether marked or not)
        cur3 = self._conn.execute(
            "SELECT COUNT(*) FROM messages WHERE expires_at IS NOT NULL AND expires_at <= ?",
            (now,),
        )
        total_expired = cur3.fetchone()[0]

        total_pending = sum(per_queue.values())

        return {
            "per_queue_depths": per_queue,
            "total_delivered": total_delivered,
            "total_expired": total_expired,
            "total_pending": total_pending,
        }

    def close(self) -> None:
        """Close the database connection."""
        self._conn.close()
