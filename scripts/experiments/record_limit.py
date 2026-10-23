#!/usr/bin/env python3
"""Drive one session into the TLS 1.3 traffic-key record ceiling.

The pinned v2.0.1 server does not implement KeyUpdate, so a single stream must
stop after 2^24 records. This test checks that the client uses the whole budget
(about 128 GiB of 8 KiB Vision frames), ends with an explicit error, survives as
a process, returns its descriptors, and never retries. It moves about 128 GiB
over loopback and is an opt-in experiment, not a CI job.
"""

import argparse
import json
import os
import signal
import socket
import socketserver
import struct
import subprocess
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BLOCK = b'x' * (1024 * 1024)
GIB = 1024 ** 3


def recv_exact(sock, count):
    data = bytearray()
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise EOFError('short socks reply')
        data.extend(chunk)
    return bytes(data)


class Sink(socketserver.BaseRequestHandler):
    received = 0
    done = threading.Event()

    def handle(self):
        while True:
            try:
                data = self.request.recv(len(BLOCK))
            except ConnectionResetError:
                break
            if not data:
                break
            Sink.received += len(data)
        Sink.done.set()


class Source(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            try:
                self.request.sendall(BLOCK)
            except OSError:
                break


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def socks_connect(port, host, target_port):
    sock = socket.create_connection(('127.0.0.1', port), timeout=15)
    sock.sendall(b'\x05\x01\x00')
    assert recv_exact(sock, 2) == b'\x05\x00'
    sock.sendall(b'\x05\x01\x00\x01' + socket.inet_aton(host) + struct.pack('>H', target_port))
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


def resources(pid):
    try:
        status = Path(f'/proc/{pid}/status').read_text()
        fields = {line.split(':', 1)[0]: line.split(':', 1)[1].strip()
                  for line in status.splitlines() if ':' in line}
        return {'rss_kib': int(fields['VmRSS'].split()[0]),
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
name = "limit"
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
    parser.add_argument('--work-dir', type=Path, default=ROOT / 'target/record-limit')
    parser.add_argument('--output', type=Path, default=ROOT / 'target/record-limit/report.json')
    parser.add_argument('--timeout', type=float, default=600)
    parser.add_argument('--direction', choices=['up', 'down'], default='up')
    args = parser.parse_args()
    values = read_env(args.env)
    args.work_dir.mkdir(parents=True, exist_ok=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)

    handler = Sink if args.direction == 'up' else Source
    target = Server(('127.0.0.1', 0), handler)
    threading.Thread(target=target.serve_forever, daemon=True).start()
    proxy_port = free_port()
    config = write_config(values, proxy_port, args.work_dir)
    log_path = args.work_dir / 'client.log'
    log = open(log_path, 'w')
    client = subprocess.Popen(
        [str(args.client.resolve()), 'run', '--config', str(config), '--log-level', 'warn'],
        stdout=log, stderr=subprocess.STDOUT)
    report = {'passed': False, 'direction': args.direction,
              'limitations': ['loopback', 'one session', 'not a WAN test']}
    try:
        wait_port(proxy_port)
        before = resources(client.pid)
        sock = socks_connect(proxy_port, '127.0.0.1', target.server_address[1])
        sock.settimeout(30)
        sent = 0
        received = 0
        begin = time.monotonic()
        failure = None
        try:
            if args.direction == 'up':
                while time.monotonic() - begin < args.timeout:
                    sock.sendall(BLOCK)
                    sent += len(BLOCK)
            else:
                while time.monotonic() - begin < args.timeout:
                    data = sock.recv(len(BLOCK))
                    if not data:
                        break
                    received += len(data)
        except OSError as error:
            failure = type(error).__name__
        elapsed = time.monotonic() - begin
        sock.close()
        if args.direction == 'up':
            Sink.done.wait(30)
            received = Sink.received
        after = resources(client.pid)
        log.flush()
        text = log_path.read_text()
        moved = sent if args.direction == 'up' else received
        report.update({
            'sent_bytes': sent,
            'received_bytes': received,
            'elapsed_seconds': elapsed,
            'mib_per_second': moved / (1024 * 1024) / elapsed,
            'failure': failure,
            'client_alive': client.poll() is None,
            'resources_before': before,
            'resources_after': after,
            'log_has_key_exhausted': 'key exhausted' in text,
            'log_tail': text.splitlines()[-8:],
        })
        if args.direction == 'up':
            in_range = 120 * GIB <= received <= 140 * GIB
        else:
            in_range = 240 * GIB <= received <= 270 * GIB
        boundary = (
            report['log_has_key_exhausted']
            or failure == 'ConnectionResetError'
            or 'reset by peer' in text
        )
        report['boundary_reported'] = boundary
        report['passed'] = (
            client.poll() is None
            and boundary
            and in_range
            and before is not None and after is not None
            and after['fds'] <= before['fds'] + 8
        )
    finally:
        if client.poll() is None:
            client.send_signal(signal.SIGINT)
            try:
                client.wait(10)
            except subprocess.TimeoutExpired:
                client.kill()
                client.wait()
        target.shutdown()
        target.server_close()
        log.close()
        args.output.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
