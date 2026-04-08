"""
Async TLS server for the tactical relay service.

Implements mTLS, 4-byte length-prefixed message framing, per-IP rate limiting,
and connection counting. Messages are passed through the auth → routing → queue
pipeline and a DeliveryAck is sent back to the sender.
"""

from __future__ import annotations

import asyncio
import collections
import logging
import ssl
import struct
import time
from typing import Callable, Deque, Optional

from tactical_relay.audit import AuditLogger
from tactical_relay.auth import AuthManager
from tactical_relay.messages_pb2 import DeliveryAck, TacticalMessage
from tactical_relay.queues import QueueManager
from tactical_relay.router import RoutingEngine

logger = logging.getLogger(__name__)

# 4-byte big-endian unsigned int for length prefix
_LENGTH_STRUCT = struct.Struct("!I")
_MAX_MESSAGE_BYTES = 10 * 1024 * 1024  # 10 MB hard cap


class RateLimiter:
    """
    Per-IP sliding window rate limiter.

    Tracks timestamps of recent requests for each IP address and rejects
    requests that exceed ``max_per_second``.
    """

    def __init__(self, max_per_second: int) -> None:
        """
        Initialise the RateLimiter.

        Args:
            max_per_second: Maximum allowed requests per second per IP.
        """
        self._max = max_per_second
        self._windows: dict[str, Deque[float]] = collections.defaultdict(collections.deque)

    def is_allowed(self, ip: str) -> bool:
        """
        Check whether the given IP is within its rate limit.

        Args:
            ip: Client IP address string.

        Returns:
            True if the request is allowed, False if it exceeds the limit.
        """
        now = time.monotonic()
        window = self._windows[ip]
        cutoff = now - 1.0  # 1-second sliding window
        while window and window[0] <= cutoff:
            window.popleft()
        if len(window) >= self._max:
            return False
        window.append(now)
        return True

    def remove_ip(self, ip: str) -> None:
        """Remove tracking data for a disconnected IP."""
        self._windows.pop(ip, None)


class TLSServer:
    """
    Asyncio TLS server implementing the tactical relay transport.

    Accepts mTLS connections, reads length-prefixed protobuf messages,
    authenticates the sender, routes to appropriate queues, and sends back
    a DeliveryAck.
    """

    def __init__(
        self,
        host: str,
        port: int,
        certfile: str,
        keyfile: str,
        ca_bundle: str,
        auth_manager: AuthManager,
        queue_manager: QueueManager,
        routing_engine: RoutingEngine,
        audit_logger: AuditLogger,
        rate_limit_per_ip: int = 100,
        max_connections: int = 1000,
    ) -> None:
        """
        Initialise the TLSServer.

        Args:
            host: Bind address.
            port: TCP port to listen on.
            certfile: Path to server certificate PEM.
            keyfile: Path to server private key PEM.
            ca_bundle: Path to CA certificate bundle PEM for client verification.
            auth_manager: Handles sender authentication and authorisation.
            queue_manager: Manages persistent message queues.
            routing_engine: Determines destination queues for messages.
            audit_logger: Writes structured audit log entries.
            rate_limit_per_ip: Maximum messages per second per client IP.
            max_connections: Maximum concurrent connections.
        """
        self._host = host
        self._port = port
        self._certfile = certfile
        self._keyfile = keyfile
        self._ca_bundle = ca_bundle
        self._auth = auth_manager
        self._queues = queue_manager
        self._router = routing_engine
        self._audit = audit_logger
        self._rate_limiter = RateLimiter(rate_limit_per_ip)
        self._max_connections = max_connections

        self._active_connections = 0
        self._messages_processed = 0
        self._error_counts: dict[str, int] = {}
        self._server: Optional[asyncio.AbstractServer] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start listening for TLS connections."""
        ssl_ctx = self._build_ssl_context()
        self._server = await asyncio.start_server(
            self._handle_client,
            host=self._host,
            port=self._port,
            ssl=ssl_ctx,
        )
        addr = self._server.sockets[0].getsockname() if self._server.sockets else (self._host, self._port)
        logger.info("TLS server listening on %s:%s", addr[0], addr[1])

    async def stop(self) -> None:
        """Gracefully stop the server."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            logger.info("TLS server stopped")

    def _build_ssl_context(self) -> ssl.SSLContext:
        """Build an mTLS SSLContext."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=self._certfile, keyfile=self._keyfile)
        ctx.load_verify_locations(cafile=self._ca_bundle)
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = False
        # Require TLS 1.2 minimum; upgrade to TLSv1_3 in environments
        # where all clients support it.
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        return ctx

    # ------------------------------------------------------------------
    # Connection handling
    # ------------------------------------------------------------------

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """
        Handle a single client connection.

        Reads messages in a loop until the connection closes or an error
        occurs. Each message is processed through auth → routing → queue.

        Args:
            reader: Async stream reader.
            writer: Async stream writer.
        """
        peer = writer.get_extra_info("peername", ("unknown", 0))
        ip = peer[0]

        if self._active_connections >= self._max_connections:
            logger.warning("Max connections reached (%d), rejecting %s", self._max_connections, ip)
            writer.close()
            return

        self._active_connections += 1
        logger.debug("Client connected: %s (active=%d)", ip, self._active_connections)

        try:
            while True:
                message_bytes = await self._read_framed_message(reader)
                if message_bytes is None:
                    break  # connection closed

                if not self._rate_limiter.is_allowed(ip):
                    logger.warning("Rate limit exceeded for IP %s", ip)
                    self._increment_error("rate_limited")
                    ack = self._make_ack("", ip, "REJECTED")
                    await self._write_framed_message(writer, ack)
                    continue

                ack_bytes = await self._process_message(message_bytes, ip)
                await self._write_framed_message(writer, ack_bytes)

        except (asyncio.IncompleteReadError, ConnectionResetError):
            logger.debug("Client %s disconnected", ip)
        except Exception as exc:
            logger.error("Error handling client %s: %s", ip, exc)
            self._increment_error("connection_error")
        finally:
            self._active_connections -= 1
            self._rate_limiter.remove_ip(ip)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _process_message(self, raw: bytes, client_ip: str) -> bytes:
        """
        Run a raw message through auth → routing → queue pipeline.

        Args:
            raw: Serialised TacticalMessage bytes.
            client_ip: Client IP address (for logging).

        Returns:
            Serialised DeliveryAck bytes.
        """
        # Parse
        try:
            msg = TacticalMessage()
            msg.ParseFromString(raw)
        except Exception as exc:
            logger.warning("Failed to parse TacticalMessage from %s: %s", client_ip, exc)
            self._increment_error("parse_error")
            return self._make_ack("UNKNOWN", client_ip, "REJECTED")

        message_id = msg.message_id or "UNKNOWN"

        # Basic field validation
        if not msg.sender or not msg.recipients or not msg.message_id:
            logger.warning("Invalid message fields from %s (message_id=%r)", client_ip, message_id)
            self._increment_error("validation_error")
            self._audit.log(
                AuditLogger.EVENT_REJECTED,
                message_id=message_id,
                sender=msg.sender or client_ip,
                recipients=list(msg.recipients),
                classification=msg.classification,
                outcome="REJECTED_INVALID_FIELDS",
            )
            return self._make_ack(message_id, client_ip, "REJECTED")

        self._audit.log(
            AuditLogger.EVENT_RECEIVED,
            message_id=message_id,
            sender=msg.sender,
            recipients=list(msg.recipients),
            classification=msg.classification,
        )

        # Auth: validate sender
        if not self._auth.validate_sender(msg.sender, ou="", required_role=None):
            logger.warning("Unauthorized sender: %r from %s", msg.sender, client_ip)
            self._increment_error("auth_failure")
            self._audit.log(
                AuditLogger.EVENT_REJECTED,
                message_id=message_id,
                sender=msg.sender,
                recipients=list(msg.recipients),
                classification=msg.classification,
                outcome="REJECTED_UNAUTHORIZED",
            )
            return self._make_ack(message_id, client_ip, "REJECTED")

        self._audit.log(
            AuditLogger.EVENT_AUTHENTICATED,
            message_id=message_id,
            sender=msg.sender,
            recipients=list(msg.recipients),
            classification=msg.classification,
        )

        # Route
        destination = msg.recipients[0] if msg.recipients else None
        queue_names = self._router.route(
            message_id=message_id,
            sender=msg.sender,
            priority=msg.priority or 5,
            classification=msg.classification or "UNCLASSIFIED",
            destination=destination,
        )

        self._audit.log(
            AuditLogger.EVENT_ROUTED,
            message_id=message_id,
            sender=msg.sender,
            recipients=list(msg.recipients),
            classification=msg.classification,
            routing_decision=str(queue_names),
        )

        # Enqueue
        ttl = msg.ttl_seconds if msg.ttl_seconds else 0
        queued_any = False
        for queue_name in queue_names:
            success = self._queues.enqueue(
                message_id=message_id,
                recipient=queue_name,
                priority=msg.priority or 5,
                classification=msg.classification or "UNCLASSIFIED",
                payload=raw,
                ttl_seconds=ttl,
            )
            if success:
                queued_any = True
                self._audit.log(
                    AuditLogger.EVENT_QUEUED,
                    message_id=message_id,
                    sender=msg.sender,
                    recipients=[queue_name],
                    classification=msg.classification,
                    outcome="QUEUED",
                )

        if queued_any:
            self._messages_processed += 1
            return self._make_ack(message_id, client_ip, "QUEUED")
        else:
            self._increment_error("queue_full")
            self._audit.log(
                AuditLogger.EVENT_REJECTED,
                message_id=message_id,
                sender=msg.sender,
                recipients=list(msg.recipients),
                classification=msg.classification,
                outcome="REJECTED_QUEUE_FULL",
            )
            return self._make_ack(message_id, client_ip, "REJECTED")

    # ------------------------------------------------------------------
    # Framing
    # ------------------------------------------------------------------

    @staticmethod
    async def _read_framed_message(reader: asyncio.StreamReader) -> Optional[bytes]:
        """
        Read a length-prefixed message from the stream.

        Frame format: [4-byte big-endian uint32 length][payload bytes]

        Args:
            reader: Async stream reader.

        Returns:
            Raw payload bytes, or None on clean EOF.

        Raises:
            ValueError: If the declared length exceeds the hard cap.
        """
        try:
            header = await reader.readexactly(_LENGTH_STRUCT.size)
        except asyncio.IncompleteReadError:
            return None

        (length,) = _LENGTH_STRUCT.unpack(header)
        if length == 0:
            return b""
        if length > _MAX_MESSAGE_BYTES:
            raise ValueError(f"Message length {length} exceeds cap {_MAX_MESSAGE_BYTES}")

        return await reader.readexactly(length)

    @staticmethod
    async def _write_framed_message(writer: asyncio.StreamWriter, payload: bytes) -> None:
        """
        Write a length-prefixed message to the stream.

        Args:
            writer: Async stream writer.
            payload: Message bytes to send.
        """
        header = _LENGTH_STRUCT.pack(len(payload))
        writer.write(header + payload)
        await writer.drain()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _make_ack(message_id: str, recipient: str, status: str) -> bytes:
        """Serialise a DeliveryAck protobuf message."""
        ack = DeliveryAck()
        ack.message_id = message_id
        ack.recipient = recipient
        ack.status = status
        ack.timestamp = int(time.time())
        return ack.SerializeToString()

    def _increment_error(self, key: str) -> None:
        """Increment an error counter."""
        self._error_counts[key] = self._error_counts.get(key, 0) + 1

    # ------------------------------------------------------------------
    # Metrics access for health server
    # ------------------------------------------------------------------

    @property
    def active_connections(self) -> int:
        """Number of currently active client connections."""
        return self._active_connections

    @property
    def messages_processed(self) -> int:
        """Total number of messages successfully processed."""
        return self._messages_processed

    @property
    def error_counts(self) -> dict[str, int]:
        """Snapshot of error counters."""
        return dict(self._error_counts)


# ---------------------------------------------------------------------------
# Framing utilities (exposed for testing)
# ---------------------------------------------------------------------------

def frame_message(payload: bytes) -> bytes:
    """
    Wrap payload with a 4-byte big-endian length prefix.

    Args:
        payload: Raw message bytes.

    Returns:
        Length-prefixed bytes ready to send.
    """
    return _LENGTH_STRUCT.pack(len(payload)) + payload


def parse_frame(data: bytes) -> tuple[int, bytes]:
    """
    Parse a length-prefixed frame.

    Args:
        data: Bytes starting with the 4-byte length prefix.

    Returns:
        Tuple of (declared_length, payload_bytes).

    Raises:
        ValueError: If data is shorter than the header.
    """
    if len(data) < _LENGTH_STRUCT.size:
        raise ValueError("Data too short to contain length prefix")
    (length,) = _LENGTH_STRUCT.unpack(data[: _LENGTH_STRUCT.size])
    payload = data[_LENGTH_STRUCT.size: _LENGTH_STRUCT.size + length]
    return length, payload
