#!/usr/bin/env python3
"""A loopback TCP echo target for the interop node's `direct` route.

The v2.0.1 node dials this server exactly as it dials a real destination: it
connects after authenticating the request and relaying begins. So bytes that
travel request -> node -> here -> node -> tunnel and back prove the whole
session path at once, including that the node really reached the target rather
than merely accepting the tunnel.

One thread per accepted connection, each echoing only its own socket, so
concurrent interop sessions can never see one another's bytes.
"""

from __future__ import annotations

import argparse
import socket
import threading


def echo(client: socket.socket) -> None:
    with client:
        try:
            while True:
                data = client.recv(65536)
                if not data:
                    return
                client.sendall(data)
        except OSError:
            # The node half-closes with close_notify and then FIN; an aborted
            # tunnel resets. Either way this connection is over.
            return


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--accept", required=True, help="host:port to listen on")
    arguments = parser.parse_args()
    host, _, port = arguments.accept.rpartition(":")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, int(port)))
    listener.listen(128)
    print(f"echo listening on {host}:{port}", flush=True)
    threads: list[threading.Thread] = []
    try:
        while True:
            client, _ = listener.accept()
            thread = threading.Thread(target=echo, args=(client,), daemon=True)
            thread.start()
            threads.append(thread)
    except KeyboardInterrupt:
        pass
    finally:
        listener.close()


if __name__ == "__main__":
    main()
