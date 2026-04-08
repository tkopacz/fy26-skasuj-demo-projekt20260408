"""Tests for the configuration module."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
import yaml

from tactical_relay.config import ServiceConfig, load_config


class TestLoadFromYAML:
    """Tests for loading configuration from YAML files."""

    def test_load_minimal_config(self, tmp_path):
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text(
            yaml.dump({
                "transport": {"port": 9443},
                "log_level": "DEBUG",
            }),
            encoding="utf-8",
        )
        cfg = load_config(str(cfg_file))
        assert cfg.transport.port == 9443
        assert cfg.log_level == "DEBUG"

    def test_load_full_config(self, tmp_path):
        cfg_file = tmp_path / "config_full.yaml"
        cfg_data = {
            "transport": {
                "host": "0.0.0.0",
                "port": 8443,
                "certfile": "certs/server.crt",
                "keyfile": "certs/server.key",
                "ca_bundle": "certs/ca.crt",
                "rate_limit_per_ip": 50,
                "max_connections": 500,
            },
            "auth": {
                "db_path": "data/auth.db",
                "crl_path": "certs/ca.crl",
            },
            "queues": {
                "db_path": "data/queues.db",
                "max_depth_per_queue": 5000,
                "default_ttl_seconds": 1800,
            },
            "audit": {
                "log_path": "logs/audit.jsonl",
                "max_bytes": 50000000,
                "backup_count": 5,
            },
            "health": {"host": "127.0.0.1", "port": 8080},
            "routing": {"rules_file": "config/rules.yaml"},
            "log_level": "WARNING",
        }
        cfg_file.write_text(yaml.dump(cfg_data), encoding="utf-8")
        cfg = load_config(str(cfg_file))
        assert cfg.transport.port == 8443
        assert cfg.transport.max_connections == 500
        assert cfg.queues.max_depth_per_queue == 5000
        assert cfg.audit.backup_count == 5
        assert cfg.log_level == "WARNING"

    def test_defaults_applied_when_no_file(self):
        cfg = load_config(None)
        assert cfg.transport.port == 8443
        assert cfg.transport.host == "0.0.0.0"
        assert cfg.queues.default_ttl_seconds == 3600
        assert cfg.log_level == "INFO"

    def test_nonexistent_file_raises(self):
        with pytest.raises(FileNotFoundError):
            load_config("/nonexistent/path/config.yaml")


class TestEnvOverrides:
    """Tests for environment variable overrides."""

    def test_transport_port_override(self, monkeypatch):
        monkeypatch.setenv("RELAY_TRANSPORT_PORT", "9999")
        cfg = load_config(None)
        assert cfg.transport.port == 9999

    def test_log_level_override(self, monkeypatch):
        monkeypatch.setenv("RELAY_LOG_LEVEL", "ERROR")
        cfg = load_config(None)
        assert cfg.log_level == "ERROR"

    def test_hmac_secret_override(self, monkeypatch):
        monkeypatch.setenv("RELAY_AUDIT_HMAC_SECRET", "my-super-secret")
        cfg = load_config(None)
        assert cfg.audit.hmac_secret == "my-super-secret"

    def test_invalid_port_env_raises(self, monkeypatch):
        monkeypatch.setenv("RELAY_TRANSPORT_PORT", "not-a-number")
        with pytest.raises(ValueError):
            load_config(None)

    def test_int_conversion(self, monkeypatch):
        monkeypatch.setenv("RELAY_TRANSPORT_MAX_CONNECTIONS", "250")
        cfg = load_config(None)
        assert cfg.transport.max_connections == 250


class TestValidation:
    """Tests for configuration validation."""

    def test_invalid_port_zero_raises(self, tmp_path):
        cfg_file = tmp_path / "bad.yaml"
        cfg_file.write_text(yaml.dump({"transport": {"port": 0}}))
        with pytest.raises(ValueError, match="port"):
            load_config(str(cfg_file))

    def test_invalid_port_too_large_raises(self, tmp_path):
        cfg_file = tmp_path / "bad2.yaml"
        cfg_file.write_text(yaml.dump({"transport": {"port": 99999}}))
        with pytest.raises(ValueError, match="port"):
            load_config(str(cfg_file))

    def test_invalid_log_level_raises(self, tmp_path):
        cfg_file = tmp_path / "bad3.yaml"
        cfg_file.write_text(yaml.dump({"log_level": "VERBOSE"}))
        with pytest.raises(ValueError, match="log_level"):
            load_config(str(cfg_file))

    def test_invalid_max_depth_raises(self, tmp_path):
        cfg_file = tmp_path / "bad4.yaml"
        cfg_file.write_text(yaml.dump({"queues": {"max_depth_per_queue": 0}}))
        with pytest.raises(ValueError, match="max_depth_per_queue"):
            load_config(str(cfg_file))

    def test_negative_rate_limit_raises(self, tmp_path):
        cfg_file = tmp_path / "bad5.yaml"
        cfg_file.write_text(yaml.dump({"transport": {"rate_limit_per_ip": -1}}))
        with pytest.raises(ValueError, match="rate_limit_per_ip"):
            load_config(str(cfg_file))

    def test_valid_config_passes(self, tmp_path):
        cfg_file = tmp_path / "ok.yaml"
        cfg_file.write_text(yaml.dump({"log_level": "INFO"}))
        cfg = load_config(str(cfg_file))
        assert cfg is not None
