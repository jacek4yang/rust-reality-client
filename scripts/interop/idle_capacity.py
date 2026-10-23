#!/usr/bin/env python3
"""Open the full local-connection ceiling and verify memory and descriptors.

Each established connection holds its relay buffers, so this measures the real
per-connection cost at MAX_LOCAL_CONNECTIONS and checks that closing them
returns descriptors. Echo traffic is one byte each; this is a capacity test,
not a throughput test.
"""

import argparse
import json
import os
import signal
import socket
import struct
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def recv_exact(sock, count):
    data = bytearray()
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise EOFError('short read')
        data.extend(chunk)
    return bytes(data)


def socks_connect(proxy_port, host, port):
    sock = socket.create_connection(('127.0.0.1', proxy_port), timeout=15)
    sock.sendall(b'\x05\x01\x00')
    assert recv_exact(sock, 2) == b'\x05\x00'
    sock.sendall(b'\x05\x01\x00\x01' + socket.inet_aton(host) + struct.pack('>H', port))
    reply = recv_exact(sock, 10)
    assert reply[:2] == b'\x05\x00', reply
    return sock


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def wait_port(port):
    for _ in range(300):
        try:
            socket.create_connection(('127.0.0.1', port), 0.1).close()
            return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(port)


def stats(pid):
    try:
        status = Path(f'/proc/{pid}/status').read_text()
        fields = {line.split(':', 1)[0]: line.split(':', 1)[1].strip()
                  for line in status.splitlines() if ':' in line}
        return {'rss_kib': int(fields['VmRSS'].split()[0]),
                'threads': int(fields['Threads']),
                'fds': len(os.listdir(f'/proc/{pid}/fd'))}
    except OSError:
        return None


def read_env(path):
    values = {}
    for line in Path(path).read_text().splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            values[key] = value
    return values


def write_config(values, port, work):
    host, server_port = values['RRC_INTEROP_ADDR'].rsplit(':', 1)
    path = work / 'client.toml'
    path.write_text(f'''[listen]
socks5 = "127.0.0.1:{port}"
http = ""

[[node]]
name = "capacity"
address = "{host}"
port = {server_port}
userId = "{values['RRC_INTEROP_USER_ID']}"

[node.reality]
publicKey = "{values['RRC_INTEROP_PUBLIC_KEY']}"
shortId = "{values['RRC_INTEROP_SHORT_ID']}"
serverName = "{values['RRC_INTEROP_SERVER_NAME']}"
fingerprint = "chrome"
''')
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--client', type=Path, default=ROOT / 'target/release/rust-reality-client')
    parser.add_argument('--env', type=Path, default=ROOT / 'target/interop/handoff.env')
    parser.add_argument('--connections', type=int, default=256)
    parser.add_argument('--work-dir', type=Path, default=ROOT / 'target/idle-capacity')
    parser.add_argument('--output', type=Path, default=ROOT / 'target/idle-capacity/report.json')
    args = parser.parse_args()
    values = read_env(args.env)
    args.work_dir.mkdir(parents=True, exist_ok=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    echo_host, echo_port = values['RRC_INTEROP_ECHO'].rsplit(':', 1)
    echo_port = int(echo_port)

    port = free_port()
    config = write_config(values, port, args.work_dir)
    log = open(args.work_dir / 'client.log', 'w')
    client = subprocess.Popen(
        [str(args.client.resolve()), 'run', '--config', str(config), '--log-level', 'warn'],
        stdout=log, stderr=subprocess.STDOUT)
    report = {'passed': False, 'requested_connections': args.connections,
              'limitations': ['loopback', 'one-byte echo per connection']}
    sockets = []
    try:
        wait_port(port)
        before = stats(client.pid)
        peak = before
        opened = 0
        for _ in range(args.connections):
            sock = socks_connect(port, echo_host, echo_port)
            sock.sendall(b'x')
            assert recv_exact(sock, 1) == b'x'
            sockets.append(sock)
            opened += 1
            value = stats(client.pid)
            if value and (peak is None or value['rss_kib'] > peak['rss_kib']):
                peak = value
        loaded = stats(client.pid)
        # Every connection must still answer after the ceiling was reached.
        for sock in sockets[::32]:
            sock.sendall(b'y')
            assert recv_exact(sock, 1) == b'y'
        for sock in sockets:
            sock.close()
        sockets.clear()
        after = None
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            after = stats(client.pid)
            if before and after and after['fds'] <= before['fds'] + 4:
                break
            time.sleep(0.2)
        report.update({
            'opened': opened,
            'before': before,
            'loaded': loaded,
            'peak': peak,
            'after': after,
            'rss_per_connection_kib': (
                (loaded['rss_kib'] - before['rss_kib']) / opened
                if loaded and before and opened else None),
        })
        report['passed'] = (
            client.poll() is None
            and opened == args.connections
            and before is not None and loaded is not None and after is not None
            and after['fds'] <= before['fds'] + 4
            and loaded['rss_kib'] <= before['rss_kib'] + 160 * 1024
        )
    finally:
        for sock in sockets:
            sock.close()
        if client.poll() is None:
            client.send_signal(signal.SIGINT)
            try:
                client.wait(10)
            except subprocess.TimeoutExpired:
                client.kill()
                client.wait()
        log.close()
        args.output.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
