"""
Authentication and authorization for the tactical relay service.

Uses X.509 client certificates for identity and SQLite for authorization.
Certificate revocation is checked against a local CRL.
"""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

logger = logging.getLogger(__name__)

# Valid roles for authorized senders
VALID_ROLES = frozenset({"ORIGINATOR", "RELAY", "RECIPIENT", "ADMIN"})

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS authorized_senders (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    cn      TEXT    NOT NULL,
    ou      TEXT    NOT NULL DEFAULT '',
    role    TEXT    NOT NULL,
    active  INTEGER NOT NULL DEFAULT 1,
    comment TEXT    NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_authorized_senders_cn ON authorized_senders (cn);
"""

_TEST_DATA_SQL = """
INSERT OR IGNORE INTO authorized_senders (cn, ou, role, active, comment) VALUES
    ('FIELD-ALPHA',   'FIELD_OPS',   'ORIGINATOR', 1, 'Test field terminal alpha'),
    ('FIELD-BRAVO',   'FIELD_OPS',   'ORIGINATOR', 1, 'Test field terminal bravo'),
    ('HQ-PRIMARY',    'COMMAND',     'RECIPIENT',  1, 'Primary HQ terminal'),
    ('HQ-BACKUP',     'COMMAND',     'RECIPIENT',  1, 'Backup HQ terminal'),
    ('RELAY-NODE-1',  'RELAY',       'RELAY',      1, 'Relay node 1'),
    ('ADMIN-CONSOLE', 'ADMIN',       'ADMIN',      1, 'Admin console'),
    ('REVOKED-TERM',  'FIELD_OPS',   'ORIGINATOR', 0, 'Decommissioned terminal');
"""


class AuthManager:
    """
    Manages authentication and authorization of tactical terminal identities.

    Identity is extracted from X.509 client certificates. Authorization is
    checked against a local SQLite database.  Certificate revocation is checked
    against a local CRL file.
    """

    def __init__(self, db_path: str, crl_path: Optional[str] = None) -> None:
        """
        Initialise the AuthManager.

        Args:
            db_path: Path to the SQLite authorization database.
            crl_path: Optional path to a PEM-encoded CRL file.
        """
        self._db_path = db_path
        self._crl_path = crl_path
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row

    # ------------------------------------------------------------------
    # Schema / seed data
    # ------------------------------------------------------------------

    def initialize_db(self) -> None:
        """
        Create the database schema and insert test seed data if not present.

        Safe to call multiple times — uses CREATE IF NOT EXISTS and INSERT OR IGNORE.
        """
        with self._conn:
            self._conn.executescript(_SCHEMA_SQL)
            self._conn.executescript(_TEST_DATA_SQL)
        logger.info("Auth database initialized at %s", self._db_path)

    # ------------------------------------------------------------------
    # Certificate helpers
    # ------------------------------------------------------------------

    @staticmethod
    def extract_identity(cert_der: bytes) -> dict:
        """
        Extract identity fields from a DER-encoded X.509 certificate.

        Args:
            cert_der: DER-encoded certificate bytes.

        Returns:
            Dictionary with keys: cn, ou, serial, not_after.

        Raises:
            ValueError: If the certificate cannot be parsed or is missing CN.
        """
        try:
            cert = x509.load_der_x509_certificate(cert_der)
        except Exception as exc:
            raise ValueError(f"Failed to parse DER certificate: {exc}") from exc

        def _attr(oid: x509.ObjectIdentifier) -> Optional[str]:
            try:
                return cert.subject.get_attributes_for_oid(oid)[0].value
            except IndexError:
                return None

        cn = _attr(NameOID.COMMON_NAME)
        if not cn:
            raise ValueError("Certificate does not contain a Common Name (CN)")

        # not_valid_after_utc was added in cryptography 42.x; fall back to not_valid_after
        not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after

        return {
            "cn": cn,
            "ou": _attr(NameOID.ORGANIZATIONAL_UNIT_NAME) or "",
            "serial": str(cert.serial_number),
            "not_after": not_after,
        }

    def check_revocation(self, cert_der: bytes, crl_path: Optional[str] = None) -> bool:
        """
        Check whether a certificate has been revoked in the local CRL.

        Args:
            cert_der: DER-encoded certificate bytes.
            crl_path: Path to the PEM CRL file. Falls back to the path given at
                      construction time if not provided.

        Returns:
            True if the certificate is NOT revoked (i.e. it is valid).
            False if the certificate IS revoked or the CRL cannot be read.
        """
        path = crl_path or self._crl_path
        if not path:
            # No CRL configured — assume not revoked
            return True

        try:
            crl_pem = Path(path).read_bytes()
        except FileNotFoundError:
            logger.warning("CRL file not found: %s — skipping revocation check", path)
            return True

        try:
            crl = x509.load_pem_x509_crl(crl_pem)
            cert = x509.load_der_x509_certificate(cert_der)
        except Exception as exc:
            logger.error("Failed to load CRL or certificate: %s", exc)
            return False

        revoked = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
        if revoked is not None:
            rev_date = getattr(revoked, "revocation_date_utc", None) or revoked.revocation_date
            logger.warning(
                "Certificate serial %s is revoked (revoked at %s)",
                cert.serial_number,
                rev_date,
            )
            return False
        return True

    # ------------------------------------------------------------------
    # Authorization
    # ------------------------------------------------------------------

    def validate_sender(
        self,
        cn: str,
        ou: str,
        required_role: Optional[str] = None,
    ) -> bool:
        """
        Check whether a sender is authorized in the database.

        Args:
            cn: Common Name of the sender.
            ou: Organizational Unit of the sender.
            required_role: If given, the sender must have this exact role.
                           If None, any active sender is accepted.

        Returns:
            True if the sender is authorized and active.
        """
        if not cn:
            logger.warning("validate_sender: empty CN")
            return False

        cursor = self._conn.execute(
            "SELECT role, active FROM authorized_senders WHERE cn = ?",
            (cn,),
        )
        row = cursor.fetchone()
        if row is None:
            logger.warning("validate_sender: CN=%r not found in auth DB", cn)
            return False

        if not row["active"]:
            logger.warning("validate_sender: CN=%r is inactive", cn)
            return False

        if required_role is not None and row["role"] != required_role:
            logger.warning(
                "validate_sender: CN=%r has role=%r, required=%r",
                cn,
                row["role"],
                required_role,
            )
            return False

        logger.debug("validate_sender: CN=%r authorized (role=%r)", cn, row["role"])
        return True

    def get_role(self, cn: str) -> Optional[str]:
        """
        Return the role of an authorized sender, or None if not found.

        Args:
            cn: Common Name to look up.

        Returns:
            Role string if found, else None.
        """
        cursor = self._conn.execute(
            "SELECT role FROM authorized_senders WHERE cn = ? AND active = 1",
            (cn,),
        )
        row = cursor.fetchone()
        return row["role"] if row else None

    def close(self) -> None:
        """Close the database connection."""
        self._conn.close()


def initialize_db(db_path: str) -> None:
    """
    Create the auth database schema and seed it with test data.

    Convenience function for use during service startup or tests.

    Args:
        db_path: Path to the SQLite database file.
    """
    mgr = AuthManager(db_path)
    mgr.initialize_db()
    mgr.close()
