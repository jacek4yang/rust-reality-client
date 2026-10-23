#!/usr/bin/env python3
"""Bulk, concurrency, latency and resource stability through one live node.

Every transferred byte is checked against a SHA-256 digest. The script also
measures one-connection ping-pong and fresh-connection setup times, and samples
the client's RSS and descriptor count before, during and after the workload.
It refuses to report success on a digest mismatch, a latency outlier or a
descriptor/memory leak. Loopback only; throughput is diagnostic, not a WAN
capacity claim.
"""

import argparse
import hashlib
import json
import os
import signal
import socket
import socketserver
import struct
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

BLOCK = bytes(range(256)) * 256


def expected_digest(size):
    digest = hashlib.sha256()
    left = size
    while left:
        chunk = BLOCK[:min(left, len(BLOCK))]
        digest.update(chunk)
        left -= len(chunk)
    return digest.digest()


def recv_exact(sock, count):
    parts = []
    left = count
    while left:
        data = sock.recv(left)
        if not data:
            raise EOFError(f'wanted {count} bytes, got {count - left}')
        parts.append(data)
        left -= len(data)
    return b''.join(parts)


class Sink(socketserver.BaseRequestHandler):
    size = 0

    def handle(self):
        digest = hashlib.sha256()
        left = self.size
        while left:
            data = self.request.recv(min(left, len(BLOCK)))
            if not data:
                raise EOFError('upload truncated')
            digest.update(data)
            left -= len(data)
        self.request.sendall(digest.digest())


class Source(socketserver.BaseRequestHandler):
    size = 0

    def handle(self):
        left = self.size
        while left:
            self.request.sendall(BLOCK[:min(left, len(BLOCK))])
            left -= min(left, len(BLOCK))


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def socks_connect(proxy_port, host, port):
    sock = socket.create_connection(('127.0.0.1', proxy_port), timeout=15)
    sock.sendall(b'\x05\x01\x00')
    assert recv_exact(sock, 2) == b'\x05\x00'
    sock.sendall(b'\x05\x01\x00\x01' + socket.inet_aton(host) + struct.pack('>H', port))
    reply = recv_exact(sock, 10)
    assert reply[:2] == b'\x05\x00', reply
    return sock


def wait_port(port):
    for _ in range(300):
        try:
            socket.create_connection(('127.0.0.1', port), 0.1).close()
            return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(port)


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def process_stats(pid):
    try:
        status = Path(f'/proc/{pid}/status').read_text()
        fields = {line.split(':', 1)[0]: line.split(':', 1)[1].strip()
                  for line in status.splitlines() if ':' in line}
        stat = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
        fds = len(os.listdir(f'/proc/{pid}/fd'))
    except OSError:
        return None
    ticks = os.sysconf('SC_CLK_TCK')
    return {
        'rss_kib': int(fields['VmRSS'].split()[0]),
        'threads': int(fields['Threads']),
        'fds': fds,
        'cpu_seconds': (int(stat[11]) + int(stat[12])) / ticks,
    }


def percentile(values, point):
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round(point / 100 * (len(ordered) - 1))))
    return ordered[index]


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
name = "stability"
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


def upload(proxy_port, target_port, size, expected):
    sock = socks_connect(proxy_port, '127.0.0.1', target_port)
    try:
        left = size
        while left:
            chunk = BLOCK[:min(left, len(BLOCK))]
            sock.sendall(chunk)
            left -= len(chunk)
        actual = recv_exact(sock, 32)
        if actual != expected:
            raise AssertionError('upload digest mismatch')
    finally:
        sock.close()


def download(proxy_port, target_port, size, expected):
    sock = socks_connect(proxy_port, '127.0.0.1', target_port)
    try:
        digest = hashlib.sha256()
        left = size
        while left:
            data = sock.recv(min(left, len(BLOCK)))
            if not data:
                raise EOFError('download truncated')
            digest.update(data)
            left -= len(data)
        if digest.digest() != expected:
            raise AssertionError('download digest mismatch')
    finally:
        sock.close()


def ping_pong(proxy_port, host, port, count):
    sock = socks_connect(proxy_port, host, port)
    samples = []
    try:
        for index in range(count):
            payload = struct.pack('>Q', index) * 2
            begin = time.monotonic()
            sock.sendall(payload)
            assert recv_exact(sock, len(payload)) == payload
            samples.append(time.monotonic() - begin)
    finally:
        sock.close()
    return samples


def connection_setup(proxy_port, host, port, count):
    samples = []
    for _ in range(count):
        begin = time.monotonic()
        sock = socks_connect(proxy_port, host, port)
        try:
            sock.sendall(b'x')
            assert recv_exact(sock, 1) == b'x'
        finally:
            sock.close()
        samples.append(time.monotonic() - begin)
    return samples


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--client', type=Path, required=True)
    parser.add_argument('--env', type=Path, default=Path('target/interop/handoff.env'))
    parser.add_argument('--mib', type=int, default=64)
    parser.add_argument('--streams', type=int, default=8)
    parser.add_argument('--rounds', type=int, default=2)
    parser.add_argument('--pings', type=int, default=500)
    parser.add_argument('--setups', type=int, default=30)
    parser.add_argument('--work-dir', type=Path, default=Path('target/bulk-stability'))
    parser.add_argument('--output', type=Path, default=Path('target/bulk-stability/report.json'))
    args = parser.parse_args()
    assert args.mib > 0 and args.streams > 0 and args.rounds > 0

    size = args.mib * 1024 * 1024
    expected = expected_digest(size)
    values = read_env(args.env)
    args.work_dir.mkdir(parents=True, exist_ok=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)

    Sink.size = size
    Source.size = size
    sink = Server(('127.0.0.1', 0), Sink)
    source = Server(('127.0.0.1', 0), Source)
    for server in (sink, source):
        threading.Thread(target=server.serve_forever, daemon=True).start()

    proxy_port = free_port()
    config = write_config(values, proxy_port, args.work_dir)
    log = open(args.work_dir / 'client.log', 'w')
    client = subprocess.Popen(
        [str(args.client.resolve()), 'run', '--config', str(config), '--log-level', 'warn'],
        stdout=log, stderr=subprocess.STDOUT)
    report = {
        'size_mib': args.mib,
        'streams': args.streams,
        'rounds': args.rounds,
        'passed': False,
        'limitations': ['loopback', 'Python sink/source', 'not WAN', 'not a production capacity claim'],
        'transfers': [],
    }
    try:
        wait_port(proxy_port)
        before = process_stats(client.pid)
        samples = []
        stop = threading.Event()

        def sample():
            while not stop.wait(0.1):
                value = process_stats(client.pid)
                if value is not None:
                    samples.append(value)

        sampler = threading.Thread(target=sample, daemon=True)
        sampler.start()

        for round_index in range(args.rounds):
            for direction in ('U', 'D'):
                begin = time.monotonic()
                with ThreadPoolExecutor(max_workers=args.streams) as pool:
                    jobs = []
                    for _ in range(args.streams):
                        if direction == 'U':
                            jobs.append(pool.submit(upload, proxy_port, sink.server_address[1],
                                                    size, expected))
                        else:
                            jobs.append(pool.submit(download, proxy_port, source.server_address[1],
                                                    size, expected))
                    for job in jobs:
                        job.result(timeout=180)
                wall = time.monotonic() - begin
                entry = {
                    'round': round_index + 1,
                    'direction': direction,
                    'streams': args.streams,
                    'mib': args.mib * args.streams,
                    'wall_seconds': wall,
                    'mib_per_second': args.mib * args.streams / wall,
                }
                report['transfers'].append(entry)
                print(json.dumps(entry), flush=True)

        stop.set()
        sampler.join(5)
        echo_host, echo_port = values['RRC_INTEROP_ECHO'].rsplit(':', 1)
        pings = ping_pong(proxy_port, echo_host, int(echo_port), args.pings)
        setups = connection_setup(proxy_port, echo_host, int(echo_port), args.setups)
        after = process_stats(client.pid)

        report['latency'] = {
            'pings': len(pings),
            'p50_ms': percentile(pings, 50) * 1000,
            'p95_ms': percentile(pings, 95) * 1000,
            'p99_ms': percentile(pings, 99) * 1000,
            'max_ms': max(pings) * 1000,
        }
        report['setup'] = {
            'connections': len(setups),
            'p50_ms': percentile(setups, 50) * 1000,
            'p95_ms': percentile(setups, 95) * 1000,
            'max_ms': max(setups) * 1000,
        }
        report['resources'] = {
            'before': before,
            'after': after,
            'peak_rss_kib': max((entry['rss_kib'] for entry in samples), default=None),
            'peak_fds': max((entry['fds'] for entry in samples), default=None),
        }
        if before and after:
            assert after['fds'] <= before['fds'] + 8, (before['fds'], after['fds'])
            assert after['rss_kib'] <= before['rss_kib'] + 64 * 1024, (before, after)
        assert report['latency']['p99_ms'] < 250, report['latency']
        assert report['setup']['p95_ms'] < 5000, report['setup']
        report['passed'] = True
    finally:
        for server in (sink, source):
            server.shutdown()
            server.server_close()
        if client.poll() is None:
            client.send_signal(signal.SIGINT)
            try:
                client.wait(10)
            except subprocess.TimeoutExpired:
                client.kill()
                client.wait()
        log.close()
        args.output.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'passed': report['passed'],
                          'latency': report.get('latency'),
                          'setup': report.get('setup'),
                          'resources': report.get('resources')}, indent=2))


if __name__ == '__main__':
    main()
