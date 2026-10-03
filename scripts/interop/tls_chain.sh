#!/usr/bin/env bash
# Mints the certificate chain the two TLS origins serve, into the directory given.
#
#   scripts/interop/tls_chain.sh target/interop/tls
#
# A CA signs one leaf for `localhost`, and that leaf carries a few thousand
# subjectAltName entries on purpose: its TLS 1.3 `Certificate` message is then
# larger than one 16 KiB record, so the origin's flight spans several
# `application_data` records. The node classifies the ServerHello as TLS 1.3 and
# takes Vision `Direct` at the first of those records (`server/vision.rs:2156-2157`),
# which puts the raw-mode boundary *inside* the handshake rather than after it.
#
# The chain is real rather than self-signed so the nested client can verify it:
# nothing in this fixture needs `CERT_NONE`, and a fixture that disabled
# verification could not tell a truncated handshake from a corrupt one.
set -euo pipefail

OUT="${1:?usage: tls_chain.sh <directory>}"
# Git Bash for Windows rewrites an argument that starts with `/CN=` into a drive
# path before openssl sees it; the subject here is not a path. A no-op elsewhere.
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'
# Roughly 24 KiB of names, which is what makes the certificate message fragment.
SAN_COUNT="${INTEROP_TLS_SAN_COUNT:-900}"
DAYS="${INTEROP_TLS_DAYS:-1}"

mkdir -p "$OUT"

# `-nodes` keeps the fixture non-interactive; the keys are for a loopback test
# origin and are regenerated on every bring-up.
openssl req -x509 -newkey rsa:2048 -nodes -days "$DAYS" \
  -subj /CN=RRC-Interop-CA \
  -addext basicConstraints=critical,CA:TRUE \
  -keyout "$OUT/ca.key" -out "$OUT/ca.crt" 2>/dev/null

openssl req -new -newkey rsa:2048 -nodes \
  -subj /CN=localhost \
  -keyout "$OUT/origin.key" -out "$OUT/origin.csr" 2>/dev/null

{
  echo "basicConstraints=critical,CA:FALSE"
  echo "keyUsage=critical,digitalSignature,keyEncipherment"
  echo "subjectAltName=@alt"
  echo "[alt]"
  echo "DNS.1=localhost"
  for ((index = 2; index <= SAN_COUNT; index++)); do
    # Names the client will never look up; they exist to occupy bytes, and only
    # the first entry is checked against `server_hostname`.
    echo "DNS.${index}=origin${index}.invalid"
  done
} > "$OUT/leaf.ext"

openssl x509 -req -in "$OUT/origin.csr" \
  -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" -CAcreateserial -days "$DAYS" \
  -extfile "$OUT/leaf.ext" \
  -out "$OUT/origin.crt" 2>/dev/null

rm -f "$OUT/origin.csr" "$OUT/ca.srl"
printf 'leaf %s bytes with %s subjectAltName entries\n' \
  "$(wc -c < "$OUT/origin.crt" | tr -d '[:space:]')" "$SAN_COUNT"
