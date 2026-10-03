#!/usr/bin/env python3
"""Performs one real nested TLS handshake through a tunnel this process did not build.

The Rust interop test owns the Vision session and exposes a loopback socket for
the application side; this script is that application. It is a genuine TLS peer,
so it is also the judge: OpenSSL will not finish a handshake whose bytes were
reordered, truncated or opened as something they are not. A client that keeps
sealing and unsealing outer records after the node handed the direction over raw
produces exactly one observable outcome - this handshake fails.

Verification is never disabled. The origins' certificate chain is issued by the
fixture's own CA, which this script is told to trust by path, and the hostname is
checked against the leaf's subjectAltName. That is the whole point of the fixture:
proving the tunnel carries a verifiable TLS connection rather than bytes that
merely arrive.

Prints one `key=value` line per observation and exits 0 only when the version,
the body and the end of stream are all what the caller expected.
"""

from __future__ import annotations

import argparse
import hashlib
import socket
import ssl
import sys

REQUEST = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"


class Failure(Exception):
    """Anything that makes the observation unusable as evidence."""


def read_response(stream: ssl.SSLSocket, expect_bytes: int, budget: float) -> bytes:
    headers = b""
    while b"\r\n\r\n" not in headers:
        chunk = stream.recv(4096)
        if not chunk:
            raise Failure("the origin closed before the headers were complete")
        headers += chunk
        if len(headers) > 64 * 1024:
            raise Failure("no header terminator inside 64 KiB")
    head, _, start = headers.partition(b"\r\n\r\n")
    length = None
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            length = int(value.strip())
    if not length or length != expect_bytes:
        raise Failure(f"content-length was {length}, expected {expect_bytes}")

    body = bytearray(start)
    stream.settimeout(budget)
    while len(body) < length:
        chunk = stream.recv(65536)
        if not chunk:
            raise Failure(f"the origin stopped after {len(body)} of {length} bytes")
        body += chunk
    for index, byte in enumerate(body):
        if byte != index % 251:
            raise Failure(f"body byte {index} was {byte}, expected {index % 251}")
    trailer = stream.recv(4096)
    if trailer:
        raise Failure(f"{len(trailer)} bytes arrived after the declared body")
    return bytes(body)


def observe(arguments: argparse.Namespace) -> dict[str, object]:
    plain = socket.create_connection(
        (arguments.connect_host, arguments.connect_port), timeout=arguments.timeout
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=arguments.ca)
    stream = context.wrap_socket(plain, server_hostname=arguments.hostname)
    stream.settimeout(arguments.timeout)
    try:
        stream.do_handshake()
        # Captured before the response: OpenSSL clears the negotiated state once
        # the peer's close_notify arrives, and the version this connection used is
        # the observation the caller is waiting for.
        negotiated = stream.version()
        cipher = (stream.cipher() or ("none",))[0]
        # The leaf's DER length is what says whether the origin's `Certificate`
        # message could have fitted in one 16 KiB record: it could not, so the
        # node's `Direct` decision necessarily lands inside the handshake.
        leaf = len(stream.getpeercert(binary_form=True))
        stream.sendall(REQUEST)
        body = read_response(stream, arguments.expect_bytes, arguments.timeout)
        return {
            "version": negotiated,
            "cipher": cipher,
            "leaf": leaf,
            "bytes": len(body),
            "digest": hashlib.sha256(body).hexdigest(),
            "eof": True,
        }
    finally:
        try:
            stream.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        stream.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--connect", required=True, help="host:port of the relay's local side")
    parser.add_argument("--ca", required=True, help="PEM of the fixture CA to trust")
    parser.add_argument("--hostname", default="localhost")
    parser.add_argument("--expect-version", required=True, help="TLSv1.3 or TLSv1.2")
    parser.add_argument("--expect-bytes", type=int, default=64 * 1024)
    parser.add_argument("--timeout", type=float, default=30.0)
    arguments = parser.parse_args()

    host, _, port = arguments.connect.rpartition(":")
    arguments.connect_host = host
    arguments.connect_port = int(port)

    try:
        facts = observe(arguments)
    except (Failure, ssl.SSLError, OSError) as error:
        print(f"result=fail reason={type(error).__name__}: {error}", flush=True)
        return 1
    if facts["version"] != arguments.expect_version:
        print(
            f"result=fail reason=negotiated {facts['version']}, "
            f"expected {arguments.expect_version}",
            flush=True,
        )
        return 1
    for name, value in facts.items():
        print(f"{name}={value}", flush=True)
    print("result=ok", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
