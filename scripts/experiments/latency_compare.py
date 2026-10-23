#!/usr/bin/env python3
"""Compare one-connection round trip and fresh-connection setup with Xray.

Both clients use the same node, fingerprint and echo destination. Setup covers
the local SOCKS handshake, the REALITY handshake and the first echoed byte, so
it is the number an application sees before its first request completes.
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


def percentile(values, point):
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round(point / 100 * (len(ordered) - 1))))
    return ordered[index]


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


def configs(values, client_port, xray_port, work):
    host, server_port = values['RRC_INTEROP_ADDR'].rsplit(':', 1)
    toml = work / 'client.toml'
    toml.write_text(f'''[listen]
socks5 = "127.0.0.1:{client_port}"
http = ""

[[node]]
name = "latency"
address = "{host}"
port = {server_port}
userId = "{values['RRC_INTEROP_USER_ID']}"

[node.reality]
publicKey = "{values['RRC_INTEROP_PUBLIC_KEY']}"
shortId = "{values['RRC_INTEROP_SHORT_ID']}"
serverName = "{values['RRC_INTEROP_SERVER_NAME']}"
fingerprint = "chrome"
''')
    xray = work / 'xray.json'
    xray.write_text(json.dumps({
        'log': {'loglevel': 'warning'},
        'inbounds': [{'listen': '127.0.0.1', 'port': xray_port, 'protocol': 'socks',
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
    }))
    return toml, xray


def start(label, binary, config, port, work):
    if label == 'rust':
        command = [str(binary.resolve()), 'run', '--config', str(config),
                   '--log-level', 'warn']
    else:
        command = [str(binary.resolve()), 'run', '-config', str(config)]
    log = open(work / f'{label}.log', 'a')
    proc = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
    wait_port(port)
    return proc


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


def setup(proxy_port, host, port, count):
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
    parser.add_argument('--xray', type=Path, required=True)
    parser.add_argument('--env', type=Path, default=ROOT / 'target/interop/handoff.env')
    parser.add_argument('--pings', type=int, default=1000)
    parser.add_argument('--setups', type=int, default=50)
    parser.add_argument('--rounds', type=int, default=3)
    parser.add_argument('--work-dir', type=Path, default=ROOT / 'target/latency-compare')
    parser.add_argument('--output', type=Path, default=ROOT / 'target/latency-compare/report.json')
    args = parser.parse_args()
    values = read_env(args.env)
    args.work_dir.mkdir(parents=True, exist_ok=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    host, port = values['RRC_INTEROP_ECHO'].rsplit(':', 1)
    port = int(port)

    rust_port, xray_port = free_port(), free_port()
    toml, xray = configs(values, rust_port, xray_port, args.work_dir)
    clients = {
        'rust': start('rust', args.client, toml, rust_port, args.work_dir),
        'xray': start('xray', args.xray, xray, xray_port, args.work_dir),
    }
    report = {'pings': args.pings, 'setups': args.setups, 'rounds': [], 'passed': False}
    try:
        order = ['rust', 'xray']
        for round_index in range(args.rounds):
            for label in (order if round_index % 2 == 0 else list(reversed(order))):
                proxy = rust_port if label == 'rust' else xray_port
                pings = ping_pong(proxy, host, port, args.pings)
                setups = setup(proxy, host, port, args.setups)
                entry = {
                    'round': round_index + 1,
                    'client': label,
                    'ping_ms': {
                        'p50': percentile(pings, 50) * 1000,
                        'p95': percentile(pings, 95) * 1000,
                        'p99': percentile(pings, 99) * 1000,
                        'max': max(pings) * 1000,
                    },
                    'setup_ms': {
                        'p50': percentile(setups, 50) * 1000,
                        'p95': percentile(setups, 95) * 1000,
                        'p99': percentile(setups, 99) * 1000,
                        'max': max(setups) * 1000,
                    },
                    'resources': stats(clients[label].pid),
                }
                report['rounds'].append(entry)
                print(json.dumps(entry), flush=True)
        report['passed'] = True
    finally:
        for proc in clients.values():
            if proc.poll() is None:
                proc.send_signal(signal.SIGINT)
                try:
                    proc.wait(10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
        args.output.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'passed': report['passed']}, indent=2))


if __name__ == '__main__':
    main()
