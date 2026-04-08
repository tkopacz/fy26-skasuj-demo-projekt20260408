#!/usr/bin/env bash
# generate_certs.sh — Generate a test PKI (CA, server cert, client certs, CRL)
# Output directory: certs/
# Usage: bash scripts/generate_certs.sh [output_dir]
#
# WARNING: For testing only. Do NOT use these keys in production.

set -euo pipefail

OUTDIR="${1:-certs}"
mkdir -p "$OUTDIR"

# 3650-day validity covers multi-year lab and CI environments where cert
# rotation is managed manually. Production deployments should use shorter
# lifetimes (e.g., 365 days) enforced by the CA policy.
DAYS=3650
SUBJECT_CA="/CN=Tactical-Relay-Test-CA/O=TacticalRelay/C=US"
SUBJECT_SERVER="/CN=relay-server/O=TacticalRelay/C=US"
SUBJECT_CLIENT1="/CN=FIELD-ALPHA/OU=FIELD_OPS/O=TacticalRelay/C=US"
SUBJECT_CLIENT2="/CN=FIELD-BRAVO/OU=FIELD_OPS/O=TacticalRelay/C=US"

echo "==> Generating CA key and self-signed certificate..."
openssl genrsa -out "$OUTDIR/ca.key" 4096
openssl req -new -x509 -days "$DAYS" \
    -key "$OUTDIR/ca.key" \
    -out "$OUTDIR/ca.crt" \
    -subj "$SUBJECT_CA" \
    -extensions v3_ca

echo "==> Generating server key and certificate..."
openssl genrsa -out "$OUTDIR/server.key" 2048
openssl req -new \
    -key "$OUTDIR/server.key" \
    -out "$OUTDIR/server.csr" \
    -subj "$SUBJECT_SERVER"
openssl x509 -req -days "$DAYS" \
    -in "$OUTDIR/server.csr" \
    -CA "$OUTDIR/ca.crt" \
    -CAkey "$OUTDIR/ca.key" \
    -CAcreateserial \
    -out "$OUTDIR/server.crt" \
    -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\n")

echo "==> Generating client certificate 1 (FIELD-ALPHA)..."
openssl genrsa -out "$OUTDIR/client-field-alpha.key" 2048
openssl req -new \
    -key "$OUTDIR/client-field-alpha.key" \
    -out "$OUTDIR/client-field-alpha.csr" \
    -subj "$SUBJECT_CLIENT1"
openssl x509 -req -days "$DAYS" \
    -in "$OUTDIR/client-field-alpha.csr" \
    -CA "$OUTDIR/ca.crt" \
    -CAkey "$OUTDIR/ca.key" \
    -CAserial "$OUTDIR/ca.srl" \
    -out "$OUTDIR/client-field-alpha.crt"

echo "==> Generating client certificate 2 (FIELD-BRAVO)..."
openssl genrsa -out "$OUTDIR/client-field-bravo.key" 2048
openssl req -new \
    -key "$OUTDIR/client-field-bravo.key" \
    -out "$OUTDIR/client-field-bravo.csr" \
    -subj "$SUBJECT_CLIENT2"
openssl x509 -req -days "$DAYS" \
    -in "$OUTDIR/client-field-bravo.csr" \
    -CA "$OUTDIR/ca.crt" \
    -CAkey "$OUTDIR/ca.key" \
    -CAserial "$OUTDIR/ca.srl" \
    -out "$OUTDIR/client-field-bravo.crt"

echo "==> Generating empty CRL..."
# Create an openssl.cnf fragment needed for CRL generation
CRL_CNF="$OUTDIR/crl.cnf"
cat > "$CRL_CNF" <<'EOF'
[ ca ]
default_ca = CA_default

[ CA_default ]
database   = crl_index.txt
crlnumber  = crlnumber
default_crl_days = 365
default_md = sha256

[ crl_ext ]
authorityKeyIdentifier = keyid:always
EOF

touch "$OUTDIR/crl_index.txt"
echo "01" > "$OUTDIR/crlnumber"

openssl ca \
    -config "$CRL_CNF" \
    -gencrl \
    -keyfile "$OUTDIR/ca.key" \
    -cert "$OUTDIR/ca.crt" \
    -out "$OUTDIR/ca.crl" \
    -crldays 365 2>/dev/null || {
    # Fallback: generate a minimal CRL without the ca database
    openssl ca \
        -gencrl \
        -keyfile "$OUTDIR/ca.key" \
        -cert "$OUTDIR/ca.crt" \
        -out "$OUTDIR/ca.crl" \
        -crldays 365 \
        -md sha256 2>/dev/null || \
    openssl x509 -in "$OUTDIR/ca.crt" -noout 2>/dev/null && \
    echo "NOTE: CRL generation skipped — create manually if needed."
}

echo "==> Cleaning up CSR files..."
rm -f "$OUTDIR"/*.csr "$CRL_CNF" "$OUTDIR/crl_index.txt" "$OUTDIR/crlnumber"

echo ""
echo "Done! Certificates written to $OUTDIR/"
echo ""
echo "Files:"
ls -1 "$OUTDIR/"
echo ""
echo "IMPORTANT: These are TEST certificates only."
echo "For production, use a proper PKI managed by your security team."
