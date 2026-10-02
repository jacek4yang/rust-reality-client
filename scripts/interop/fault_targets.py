#!/usr/bin/env python3
"""Destinations with deliberate faults, for the interop node to dial.

The v2.0.1 node reaches these exactly as it reaches a real server: after it has
authenticated the request, it connects here and relaying begins. So a fault in
one of these sockets is a fault *beyond* the tunnel, which is the half of the
fault-injection matrix no in-process fake can produce — a fabricated session
would be a fabricated handshake.

Each listener is one fault shape an operator actually meets:

  late      answers, but not for a while. A healthy authenticated tunnel has to
            survive the destination's own slowness, so a client that imposes an
            idle deadline on it fails here.
  drop      accepts and closes without a byte. The destination refused to talk
            after the tunnel was already promised.
  rst       accepts and resets, SO_LINGER on with zero seconds. The same end,
            arriving as a reset rather than an orderly close.
  truncate  sends a burst, then resets mid-transfer. The shape of a download
            that dies partway: bytes arrive first, and the failure follows them.

None of these echo, so a test can tell its own bytes apart from the
destination's.
"""

from __future__ import annotations

import argparse
import socket
import struct
import threading
import time

BURST = 64 * 1024
LATE_SECONDS = 3.0
RESET = struct.pack("ii", 1, 0)


def reset(client: socket.socket) -> None:
    """Discards the send buffer and sends a RST instead of a FIN."""
    client.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, RESET)
    client.close()


def late(client: socket.socket) -> None:
    data = client.recv(4096)
    time.sleep(LATE_SECONDS)
    client.sendall(b"LATE" + data)


def drop(_client: socket.socket) -> None:
    return


def abrupt(client: socket.socket) -> None:
    reset(client)


def truncate(client: socket.socket) -> None:
    client.recv(4096)
    client.sendall(bytes(BURST))
    reset(client)


def serve(accept: str, handler) -> None:
    """Runs one fault listener until the process is asked to stop."""
    host, _, port = accept.rpartition(":")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, int(port)))
    listener.listen(128)
    print(f"{handler.__name__} listening on {host}:{port}", flush=True)
    while True:
        client, _ = listener.accept()
        threading.Thread(target=handle, args=(client, handler), daemon=True).start()


def handle(client: socket.socket, handler) -> None:
    with client:
        try:
            handler(client)
        except OSError:
            # Each of these faults ends in a broken socket, and the broken
            # socket is the point rather than an error worth reporting.
            pass


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("late", "drop", "rst", "truncate"):
        parser.add_argument(f"--{name}", required=True, help="host:port")
    arguments = parser.parse_args()

    shapes = [
        (arguments.late, late),
        (arguments.drop, drop),
        (arguments.rst, abrupt),
        (arguments.truncate, truncate),
    ]
    threads = [
        threading.Thread(target=serve, args=(accept, handler), daemon=True)
        for accept, handler in shapes
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()


if __name__ == "__main__":
    main()
