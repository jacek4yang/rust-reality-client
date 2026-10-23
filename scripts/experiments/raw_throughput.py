#!/usr/bin/env python3
"""Raw TCP throughput of two SOCKS5 clients through one REALITY server.

The sink and source are local Python servers, the network is loopback, and no
TLS origin is involved. This isolates client and tunnel cost; it is not a WAN,
TLS-origin, or production throughput claim. The server address and credentials
come from an interop handoff.env file.
"""

import argparse
import json
import signal
import socket
import socketserver
import struct
import subprocess
import threading
import time
from pathlib import Path

BLOCK = b'x' * (1024 * 1024)


def read_env(path):
    values = {}
    for line in Path(path).read_text().splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            values[key] = value
    return values


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
        left = self.size
        while left:
            data = self.request.recv(min(left, len(BLOCK)))
            if not data:
                raise EOFError('sink truncated')
            left -= len(data)
        self.request.sendall(struct.pack('>Q', self.size))


class Source(socketserver.BaseRequestHandler):
    def handle(self):
        left = self.size
        while left:
            self.request.sendall(BLOCK[:min(left, len(BLOCK))])
            left -= min(left, len(BLOCK))
        self.request.recv(1)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def socks_connect(proxy_port, host, port):
    sock = socket.create_connection(('127.0.0.1', proxy_port), timeout=10)
    sock.sendall(b'\x05\x01\x00')
    assert sock.recv(2) == b'\x05\x00'
    sock.sendall(b'\x05\x01\x00\x01' + socket.inet_aton(host) + struct.pack('>H', port))
    reply = recv_exact(sock, 10)
    assert reply[:2] == b'\x05\x00', reply
    return sock


def wait_port(port):
    for _ in range(200):
        try:
            socket.create_connection(('127.0.0.1', port), 0.1).close()
            return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(port)


def process_cpu(pid):
    fields = Path(f'/proc/{pid}/stat').read_text().split()
    return (int(fields[13]) + int(fields[14])) / 100.0


def process_rss_kib(pid):
    return int(Path(f'/proc/{pid}/statm').read_text().split()[1]) * 4096 // 1024


def upload(proxy_port, target_port, size):
    begin = time.monotonic()
    sock = socks_connect(proxy_port, '127.0.0.1', target_port)
    try:
        left = size
        while left:
            chunk = BLOCK[:min(left, len(BLOCK))]
            sock.sendall(chunk)
            left -= len(chunk)
        ack = recv_exact(sock, 8)
        assert ack == struct.pack('>Q', size), ack
    finally:
        sock.close()
    return time.monotonic() - begin


def download(proxy_port, target_port, size):
    begin = time.monotonic()
    sock = socks_connect(proxy_port, '127.0.0.1', target_port)
    try:
        left = size
        while left:
            data = sock.recv(min(left, len(BLOCK)))
            if not data:
                raise EOFError('download truncated')
            left -= len(data)
        sock.sendall(b'k')
    finally:
        sock.close()
    return time.monotonic() - begin


def write_configs(label, values, port, work):
    host, server_port = values['RRC_INTEROP_ADDR'].rsplit(':', 1)
    toml = f'''[listen]
socks5 = "127.0.0.1:{port}"
http = ""

[[node]]
name = "bench"
address = "{host}"
port = {server_port}
userId = "{values['RRC_INTEROP_USER_ID']}"

[node.reality]
publicKey = "{values['RRC_INTEROP_PUBLIC_KEY']}"
shortId = "{values['RRC_INTEROP_SHORT_ID']}"
serverName = "{values['RRC_INTEROP_SERVER_NAME']}"
fingerprint = "chrome"
'''
    xray = {
        'log': {'loglevel': 'warning'},
        'inbounds': [{'listen': '127.0.0.1', 'port': port, 'protocol': 'socks',
                      'settings': {'udp': False}}],
        'outbounds': [{
            'protocol': 'vless',
            'settings': {'vnext': [{'address': host, 'port': int(server_port),
                                     'users': [{'id': values['RRC_INTEROP_USER_ID'],
                                                'encryption': 'none',
                                                'flow': 'xtls-rprx-vision'}]}]},
            'streamSettings': {'network': 'tcp', 'security': 'reality',
                               'realitySettings': {
                                   'serverName': values['RRC_INTEROP_SERVER_NAME'],
                                   'fingerprint': 'chrome',
                                   'publicKey': values['RRC_INTEROP_PUBLIC_KEY'],
                                   'shortId': values['RRC_INTEROP_SHORT_ID']}}
        }]
    }
    if label == 'rust':
        path = work / 'client.toml'
        path.write_text(toml)
        return path
    path = work / 'xray.json'
    path.write_text(json.dumps(xray))
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--env', type=Path, default=Path('target/interop/handoff.env'))
    parser.add_argument('--client', type=Path, required=True)
    parser.add_argument('--xray', type=Path, required=True)
    parser.add_argument('--size-mib', type=int, default=256)
    parser.add_argument('--rounds', type=int, default=5)
    parser.add_argument('--rust-port', type=int, default=25001)
    parser.add_argument('--xray-port', type=int, default=25002)
    parser.add_argument('--work-dir', type=Path, default=Path('target/raw-throughput'))
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    assert args.size_mib > 0 and args.rounds > 0

    size = args.size_mib * 1024 * 1024
    Sink.size = size
    Source.size = size
    values = read_env(args.env)
    args.work_dir.mkdir(parents=True, exist_ok=True)

    sink = Server(('127.0.0.1', 0), Sink)
    source = Server(('127.0.0.1', 0), Source)
    for server in (sink, source):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    clients = {}
    try:
        for label, binary, port in [('rust', args.client, args.rust_port),
                                    ('xray', args.xray, args.xray_port)]:
            config = write_configs(label, values, port, args.work_dir)
            if label == 'rust':
                command = [str(binary.resolve()), 'run', '--config', str(config),
                           '--log-level', 'warn']
            else:
                command = [str(binary.resolve()), 'run', '-config', str(config)]
            clients[label] = subprocess.Popen(
                command, stdout=open(args.work_dir / f'{label}.log', 'a'),
                stderr=subprocess.STDOUT)
            wait_port(port)

        results = {}
        order = ['rust', 'xray']
        for round_index in range(args.rounds):
            for label in (order if round_index % 2 == 0 else list(reversed(order))):
                pid = clients[label].pid
                cpu_before = process_cpu(pid)
                up = upload(args.rust_port if label == 'rust' else args.xray_port,
                            sink.server_address[1], size)
                cpu_after_up = process_cpu(pid)
                down = download(args.rust_port if label == 'rust' else args.xray_port,
                                source.server_address[1], size)
                cpu_after = process_cpu(pid)
                entry = {
                    'upload_mib_s': args.size_mib / up,
                    'download_mib_s': args.size_mib / down,
                    'upload_cpu_seconds': cpu_after_up - cpu_before,
                    'download_cpu_seconds': cpu_after - cpu_after_up,
                    'rss_kib': process_rss_kib(pid),
                }
                results.setdefault(label, []).append(entry)
                print(label, round_index, json.dumps(entry), flush=True)

        report = {
            'size_mib': args.size_mib,
            'rounds': args.rounds,
            'results': results,
            'limitations': ['loopback', 'Python sink/source', 'raw TCP, no TLS origin',
                            'not WAN'],
        }
        text = json.dumps(report, indent=2) + '\n'
        if args.output:
            args.output.write_text(text)
        print(text)
    finally:
        for proc in clients.values():
            if proc.poll() is None:
                proc.send_signal(signal.SIGINT)
                try:
                    proc.wait(10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
        sink.shutdown()
        source.shutdown()
        sink.server_close()
        source.server_close()


if __name__ == '__main__':
    main()
