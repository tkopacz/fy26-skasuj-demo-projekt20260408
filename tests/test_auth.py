"""Tests for the authentication and authorization module."""

from __future__ import annotations

from pathlib import Path

import pytest

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from tactical_relay.auth import AuthManager, VALID_ROLES


class TestExtractIdentity:
    """Tests for AuthManager.extract_identity."""

    def test_extracts_cn_and_ou(self, client_cert_and_key):
        _, cert = client_cert_and_key
        der = cert.public_bytes(Encoding.DER)
        identity = AuthManager.extract_identity(der)
        assert identity["cn"] == "FIELD-ALPHA"
        assert identity["ou"] == "FIELD_OPS"

    def test_extracts_serial(self, client_cert_and_key):
        _, cert = client_cert_and_key
        der = cert.public_bytes(Encoding.DER)
        identity = AuthManager.extract_identity(der)
        assert "serial" in identity
        assert identity["serial"] == str(cert.serial_number)

    def test_invalid_der_raises(self):
        with pytest.raises(ValueError, match="Failed to parse DER certificate"):
            AuthManager.extract_identity(b"not a certificate")

    def test_not_after_present(self, client_cert_and_key):
        _, cert = client_cert_and_key
        der = cert.public_bytes(Encoding.DER)
        identity = AuthManager.extract_identity(der)
        assert identity["not_after"] is not None


class TestCheckRevocation:
    """Tests for AuthManager.check_revocation."""

    def test_valid_cert_not_revoked(self, auth_manager, client_cert_and_key):
        _, cert = client_cert_and_key
        der = cert.public_bytes(Encoding.DER)
        # No CRL configured → assume valid
        assert auth_manager.check_revocation(der) is True

    def test_revoked_cert_rejected(self, tmp_path, ca_cert_and_key, revoked_cert_and_crl):
        ca_cert, ca_key = ca_cert_and_key
        revoked_cert, crl_path = revoked_cert_and_crl
        mgr = AuthManager(db_path=str(tmp_path / "auth2.db"), crl_path=str(crl_path))
        der = revoked_cert.public_bytes(Encoding.DER)
        assert mgr.check_revocation(der) is False
        mgr.close()

    def test_missing_crl_file_returns_true(self, auth_manager, client_cert_and_key):
        _, cert = client_cert_and_key
        der = cert.public_bytes(Encoding.DER)
        assert auth_manager.check_revocation(der, crl_path="/nonexistent/crl.pem") is True

    def test_non_revoked_cert_with_crl(self, tmp_path, ca_cert_and_key, revoked_cert_and_crl, client_cert_and_key):
        ca_cert, ca_key = ca_cert_and_key
        _, crl_path = revoked_cert_and_crl
        _, cert = client_cert_and_key
        mgr = AuthManager(db_path=str(tmp_path / "auth3.db"), crl_path=str(crl_path))
        der = cert.public_bytes(Encoding.DER)
        # FIELD-ALPHA (serial 1001) is not in the CRL
        assert mgr.check_revocation(der) is True
        mgr.close()


class TestValidateSender:
    """Tests for AuthManager.validate_sender."""

    def test_valid_active_sender_accepted(self, auth_manager):
        assert auth_manager.validate_sender("FIELD-ALPHA", "FIELD_OPS") is True

    def test_unknown_sender_rejected(self, auth_manager):
        assert auth_manager.validate_sender("UNKNOWN-TERMINAL", "NONE") is False

    def test_inactive_sender_rejected(self, auth_manager):
        # REVOKED-TERM has active=0 in seed data
        assert auth_manager.validate_sender("REVOKED-TERM", "FIELD_OPS") is False

    def test_role_check_correct_role_accepted(self, auth_manager):
        assert auth_manager.validate_sender("FIELD-ALPHA", "FIELD_OPS", required_role="ORIGINATOR") is True

    def test_role_check_wrong_role_rejected(self, auth_manager):
        # FIELD-ALPHA is ORIGINATOR, not RECIPIENT
        assert auth_manager.validate_sender("FIELD-ALPHA", "FIELD_OPS", required_role="RECIPIENT") is False

    def test_admin_role(self, auth_manager):
        assert auth_manager.validate_sender("ADMIN-CONSOLE", "ADMIN", required_role="ADMIN") is True

    def test_relay_role(self, auth_manager):
        assert auth_manager.validate_sender("RELAY-NODE-1", "RELAY", required_role="RELAY") is True

    def test_empty_cn_rejected(self, auth_manager):
        assert auth_manager.validate_sender("", "") is False


class TestGetRole:
    """Tests for AuthManager.get_role."""

    def test_returns_role_for_known_sender(self, auth_manager):
        assert auth_manager.get_role("HQ-PRIMARY") == "RECIPIENT"

    def test_returns_none_for_unknown(self, auth_manager):
        assert auth_manager.get_role("NOBODY") is None

    def test_returns_none_for_inactive(self, auth_manager):
        # REVOKED-TERM is inactive — get_role filters by active=1
        assert auth_manager.get_role("REVOKED-TERM") is None
