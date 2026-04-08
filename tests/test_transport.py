"""Tests for the transport module."""

from __future__ import annotations

import struct
import time

import pytest

from tactical_relay.transport import RateLimiter, frame_message, parse_frame


class TestMessageFraming:
    """Tests for 4-byte length-prefix framing utilities."""

    def test_frame_message_adds_header(self):
        payload = b"hello"
        framed = frame_message(payload)
        assert len(framed) == 4 + len(payload)
        (declared_len,) = struct.unpack("!I", framed[:4])
        assert declared_len == len(payload)
        assert framed[4:] == payload

    def test_parse_frame_recovers_payload(self):
        payload = b"test-payload"
        framed = frame_message(payload)
        length, recovered = parse_frame(framed)
        assert length == len(payload)
        assert recovered == payload

    def test_frame_empty_payload(self):
        framed = frame_message(b"")
        assert len(framed) == 4
        (declared_len,) = struct.unpack("!I", framed[:4])
        assert declared_len == 0

    def test_parse_frame_short_data_raises(self):
        with pytest.raises(ValueError, match="too short"):
            parse_frame(b"\x00\x01")

    def test_frame_large_payload(self):
        # Test at the 64 KiB boundary to exercise the length-prefix with a non-trivial value
        payload = b"X" * 65536
        framed = frame_message(payload)
        length, recovered = parse_frame(framed)
        assert length == 65536
        assert recovered == payload

    def test_round_trip_binary_data(self):
        payload = bytes(range(256))
        framed = frame_message(payload)
        _, recovered = parse_frame(framed)
        assert recovered == payload

    def test_big_endian_byte_order(self):
        """Verify the length prefix is big-endian (network byte order)."""
        payload = b"A" * 256
        framed = frame_message(payload)
        # Big-endian: 256 = 0x00000100
        assert framed[:4] == b"\x00\x00\x01\x00"


class TestRateLimiter:
    """Tests for per-IP sliding window rate limiter."""

    def test_within_limit_allowed(self):
        limiter = RateLimiter(max_per_second=10)
        for _ in range(10):
            assert limiter.is_allowed("192.168.1.1") is True

    def test_exceeding_limit_rejected(self):
        limiter = RateLimiter(max_per_second=3)
        for _ in range(3):
            limiter.is_allowed("10.0.0.1")
        assert limiter.is_allowed("10.0.0.1") is False

    def test_different_ips_independent(self):
        limiter = RateLimiter(max_per_second=2)
        limiter.is_allowed("192.168.1.1")
        limiter.is_allowed("192.168.1.1")
        # ip 1 is at limit; ip 2 should still be allowed
        assert limiter.is_allowed("192.168.1.2") is True

    def test_rate_resets_after_window(self):
        """After 1 second, the sliding window resets."""
        limiter = RateLimiter(max_per_second=2)
        ip = "172.16.0.1"
        limiter.is_allowed(ip)
        limiter.is_allowed(ip)
        assert limiter.is_allowed(ip) is False

        # Manually age the timestamps to simulate 1+ second passing
        window = limiter._windows[ip]
        old_time = time.monotonic() - 2.0
        for i in range(len(window)):
            window[i] = old_time

        # Now the window should have cleared
        assert limiter.is_allowed(ip) is True

    def test_remove_ip_cleans_up(self):
        limiter = RateLimiter(max_per_second=5)
        limiter.is_allowed("1.2.3.4")
        assert "1.2.3.4" in limiter._windows
        limiter.remove_ip("1.2.3.4")
        assert "1.2.3.4" not in limiter._windows

    def test_rate_limit_one(self):
        limiter = RateLimiter(max_per_second=1)
        assert limiter.is_allowed("10.10.10.10") is True
        assert limiter.is_allowed("10.10.10.10") is False


class TestConnectionCounting:
    """Tests for connection counter in TLSServer."""

    def test_initial_connections_zero(self, test_config, audit_logger, queue_manager, auth_manager, routing_engine):
        from tactical_relay.transport import TLSServer

        server = TLSServer(
            host="127.0.0.1",
            port=19445,
            certfile=test_config.transport.certfile,
            keyfile=test_config.transport.keyfile,
            ca_bundle=test_config.transport.ca_bundle,
            auth_manager=auth_manager,
            queue_manager=queue_manager,
            routing_engine=routing_engine,
            audit_logger=audit_logger,
            rate_limit_per_ip=100,
            max_connections=10,
        )
        assert server.active_connections == 0
        assert server.messages_processed == 0

    def test_error_counts_start_empty(self, test_config, audit_logger, queue_manager, auth_manager, routing_engine):
        from tactical_relay.transport import TLSServer

        server = TLSServer(
            host="127.0.0.1",
            port=19446,
            certfile=test_config.transport.certfile,
            keyfile=test_config.transport.keyfile,
            ca_bundle=test_config.transport.ca_bundle,
            auth_manager=auth_manager,
            queue_manager=queue_manager,
            routing_engine=routing_engine,
            audit_logger=audit_logger,
        )
        assert server.error_counts == {}
