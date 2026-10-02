#!/usr/bin/env python3
"""A concurrency-safe TLS 1.3 cover for interop testing.

`openssl s_server` serves one connection at a time. A v2.0.1 node with
`reality.coverOptimization` enabled keeps warm cover connections and prebuilt
cover profiles, so a single-threaded cover gets monopolised and the node stops
answering real clients long before it should. This cover accepts as many
handshakes at once as the test throws at it, which is what a genuine `dest`
looks like from the server's side.

The handler reads until the peer closes rather than replying: the server only
needs this side's TLS 1.3 flight, and waiting for input keeps the connection
open without inventing application bytes it did not ask for.
"""

from __future__ import annotations

import argparse
import socket
import socketserver
import ssl


class CoverHandler(socketserver.BaseRequestHandler):
    """Completes a TLS 1.3 handshake and then drains the connection."""

    def handle(self) -> None:
        context: ssl.SSLContext = self.server.tls_context
        try:
            wrapped = context.wrap_socket(self.request, server_side=True)
        except (ssl.SSLError, OSError):
            return
        wrapped.settimeout(30.0)
        try:
            while wrapped.recv(4096):
                pass
        except (ssl.SSLError, OSError):
            pass
        finally:
            try:
                wrapped.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            wrapped.close()


class CoverServer(socketserver.ThreadingTCPServer):
    """Threads each accepted connection so no handshake queues behind another."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address: tuple[str, int], context: ssl.SSLContext) -> None:
        super().__init__(address, CoverHandler)
        self.tls_context = context


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--accept", default="127.0.0.1:44443")
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    arguments = parser.parse_args()

    host, _, port = arguments.accept.partition(":")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    # The server requires X25519 from its cover, so the curve is fixed rather
    # than left to whatever the peer prefers.
    context.set_ecdh_curve("X25519")
    context.load_cert_chain(certfile=arguments.cert, keyfile=arguments.key)

    with CoverServer((host, int(port)), context) as server:
        server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
