#!/usr/bin/env python3
"""Two loopback TLS origins: one a v2.0.1 node must take Direct on, one End.

Vision's transition is decided by the node reading the *destination's* bytes, so
nothing but a real destination can prove which transition a client has to follow.
A node classifies the origin's ServerHello and then acts on that classification
for the rest of the direction:

* TLS 1.3 - after a ServerHello carrying `supported_versions = 0x0304`, the
  origin's first `application_data` record makes the node write it as a
  `Direct` frame and hand the socket over raw
  (`server/vision.rs:2156-2157`, `:1391-1417`). The rest of the origin's
  handshake arrives as plaintext on the wire, not as records to be opened.
* TLS 1.2 - a ServerHello that is not TLS 1.3 makes the node write `End`
  (`:2158`) and keep sealing outer TLS records whose plaintext is the origin's
  own record layer (`DirectionState::Outer`, `:1842-1872`).

The 1.3 origin therefore serves a certificate deliberately larger than one
16 KiB TLS record: its `Certificate` spans several `application_data` records,
so the boundary falls *inside* the origin's flight. A client that keeps opening
records after `Direct` breaks the nested handshake in the middle, which is
exactly the failure this fixture exists to make visible.

Both origins answer one HTTP/1.1 request with a deterministic body and close, so
the same connection also proves bytes keep flowing in the mode the transition
left behind.
"""

from __future__ import annotations

import argparse
import socket
import socketserver
import ssl
import threading

REQUEST_END = b"\r\n\r\n"
MAX_REQUEST_BYTES = 16 * 1024


def body(length: int) -> bytes:
    """The same cyclic byte pattern the Rust bulk tests use, `length` bytes."""
    return bytes(index % 251 for index in range(length))


class OriginHandler(socketserver.BaseRequestHandler):
    """Completes a nested TLS handshake, answers one request, closes cleanly."""

    def handle(self) -> None:
        context: ssl.SSLContext = self.server.tls_context
        try:
            wrapped = context.wrap_socket(self.request, server_side=True)
        except (ssl.SSLError, OSError) as error:
            print(f"handshake failed: {error}", flush=True)
            return
        wrapped.settimeout(30.0)
        try:
            request = b""
            while REQUEST_END not in request:
                chunk = wrapped.recv(4096)
                if not chunk:
                    return
                request += chunk
                if len(request) > MAX_REQUEST_BYTES:
                    return
            payload = body(self.server.body_bytes)
            wrapped.sendall(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/octet-stream\r\n"
                + b"Content-Length: " + str(len(payload)).encode("ascii") + b"\r\n"
                b"Connection: close\r\n\r\n"
                + payload
            )
            wrapped.shutdown(socket.SHUT_RDWR)
        except (ssl.SSLError, OSError) as error:
            # An aborted tunnel is a normal end for a test origin.
            print(f"connection ended early: {error}", flush=True)
        finally:
            wrapped.close()


class OriginServer(socketserver.ThreadingTCPServer):
    """Threads each connection so no handshake queues behind another."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self, address: tuple[str, int], context: ssl.SSLContext, body_bytes: int
    ) -> None:
        super().__init__(address, OriginHandler)
        self.tls_context = context
        self.body_bytes = body_bytes


def context_for(
    cert: str, key: str, *, tls13_only: bool
) -> ssl.SSLContext:
    """A server context pinned to one protocol version, from a real chain."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert, keyfile=key)
    if tls13_only:
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
    else:
        # The whole point is that no 1.3 ServerHello can appear: a client that
        # offers 1.3 has to be pushed down to 1.2, which is what makes the node
        # classify it as non-Direct.
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def parse(address: str) -> tuple[str, int]:
    host, _, port = address.rpartition(":")
    return host, int(port)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tls13", default="127.0.0.1:14450")
    parser.add_argument("--tls12", default="127.0.0.1:14451")
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--body", type=int, default=64 * 1024)
    arguments = parser.parse_args()

    origins = [
        (
            arguments.tls13,
            context_for(arguments.cert, arguments.key, tls13_only=True),
        ),
        (
            arguments.tls12,
            context_for(arguments.cert, arguments.key, tls13_only=False),
        ),
    ]
    servers = [
        OriginServer(parse(address), context, arguments.body)
        for address, context in origins
    ]
    threads = []
    for server in servers:
        host, port = server.server_address[:2]
        print(f"tls origin on {host}:{port}", flush=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
