#!/usr/bin/env python3
"""Real-process TLS/WSS/SSE acceptance, using websockets==15.0.1 (test only).

Run in the SAME process/network namespace as the isolated upstream fixture:
  python -m venv target/soak-venv
  target/soak-venv/bin/pip install websockets==15.0.1
  INTEROP_BINARY=/path/to/pinned/v2.0.1 target/soak-venv/bin/python \
    scripts/interop/application_soak.py --seconds 3600

--seconds 86400 / 259200 opt into 24/72-hour runs. No real credentials or paid
services are used. Results never contain generated fixture authentication data.
This harness measures user-space backpressure and resets, NOT packet loss/NAT.
"""
from __future__ import annotations
import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import socketserver
import ssl
import struct
import subprocess
import threading
import time

from websockets.asyncio.client import connect
from websockets.asyncio.server import serve

ROOT = Path(__file__).resolve().parents[2]


def recv_exact(sock, count):
    data = bytearray()
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise EOFError("proxy closed before its complete answer")
        data.extend(chunk)
    return bytes(data)


def tunnel(proxy_port, origin_port, kind):
    sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=15)
    if kind == "http":
        sock.sendall(f"CONNECT 127.0.0.1:{origin_port} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode())
        reply = bytearray()
        while not reply.endswith(b"\r\n\r\n"):
            reply.extend(recv_exact(sock, 1))
            if len(reply) > 16384:
                raise AssertionError("unbounded CONNECT response")
        assert bytes(reply).startswith(b"HTTP/1.1 200 "), reply
    else:
        # Greeting + CONNECT in one write exercises SOCKS pipelining.
        sock.sendall(b"\x05\x01\x00\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", origin_port))
        assert recv_exact(sock, 2) == b"\x05\x00"
        head = recv_exact(sock, 4)
        assert head[:2] == b"\x05\x00", head
        tail = 4 if head[3] == 1 else 16
        recv_exact(sock, tail + 2)
    return sock


def pipelined_tls(proxy, target, kind, context):
    """Send CONNECT plus the real TLS ClientHello in one write, then validate TLS.

    OpenSSL's MemoryBIO is the TLS implementation; this is only socket plumbing.
    No verification is disabled and no hand-written TLS records are involved.
    """
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = context.wrap_bio(incoming, outgoing, server_side=False, server_hostname='localhost')
    try: tls.do_handshake()
    except ssl.SSLWantReadError: pass
    hello = outgoing.read()
    assert hello, 'OpenSSL produced no ClientHello'
    with socket.create_connection(('127.0.0.1', proxy), 15) as sock:
        if kind == 'http':
            prefix = f'CONNECT 127.0.0.1:{target} HTTP/1.1\r\nHost: localhost\r\n\r\n'.encode()
            sock.sendall(prefix + hello)
            answer = bytearray()
            while not answer.endswith(b'\r\n\r\n'):
                answer.extend(recv_exact(sock, 1))
                assert len(answer) <= 16384
            assert answer.startswith(b'HTTP/1.1 200 ')
        else:
            prefix = b'\x05\x01\x00\x05\x01\x00\x01\x7f\x00\x00\x01' + struct.pack('!H', target)
            sock.sendall(prefix + hello)
            assert recv_exact(sock, 2) == b'\x05\x00'
            answer = recv_exact(sock, 4)
            assert answer[:2] == b'\x05\x00'
            recv_exact(sock, (4 if answer[3] == 1 else 16) + 2)
        def flush():
            wire = outgoing.read()
            if wire: sock.sendall(wire)
        def read_wire():
            wire = sock.recv(65536)
            if not wire: raise EOFError('truncated nested TLS')
            incoming.write(wire)
        while True:
            try:
                tls.do_handshake(); flush(); break
            except ssl.SSLWantReadError:
                flush(); read_wire()
        tls.write(b'GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n'); flush()
        answer = bytearray()
        while True:
            try: answer.extend(tls.read(65536))
            except ssl.SSLWantReadError:
                flush(); read_wire(); continue
            if b'\r\n\r\n' not in answer: continue
            head, body = bytes(answer).split(b'\r\n\r\n', 1)
            length = int(next(line.split(b':',1)[1] for line in head.split(b'\r\n') if line.lower().startswith(b'content-length:')))
            if len(body) >= length:
                assert head.startswith(b'HTTP/1.1 200 ')
                assert body == bytes(i % 251 for i in range(length)), 'pipelined TLS payload changed'
                return {'tls': tls.version(), 'bytes': length}


def tls_context(folder, version, server=False):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER) if server else ssl.create_default_context(cafile=str(folder / "ca.crt"))
    context.minimum_version = context.maximum_version = version
    if server:
        context.load_cert_chain(folder / "origin.crt", folder / "origin.key")
    return context


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


async def ws_origin(ws):
    async for data in ws:
        if data == b"RESET-FIXTURE":
            ws.transport.abort()
            return
        await ws.send(data)


class SSE(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            with self.server.context.wrap_socket(self.request, server_side=True) as conn:
                conn.settimeout(20)
                head = bytearray()
                while not head.endswith(b"\r\n\r\n"):
                    head.extend(recv_exact(conn, 1))
                    if len(head) > 16384:
                        raise ValueError("request header too large")
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n")
                sequence = 0
                while time.monotonic() < self.server.deadline:
                    payload = hashlib.sha256(str(sequence).encode()).hexdigest()
                    conn.sendall(f"id: {sequence}\ndata: {payload}\n\n".encode())
                    sequence += 1
                    time.sleep(0.2)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            # Only a peer cancellation is expected here; client-side assertions
            # still fail on unexpected EOF or a missing sequence.
            pass


class SSEServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def sample_process(pid):
    status = Path(f"/proc/{pid}/status").read_text()
    fields = {line.split(':')[0]: line.split(':')[1].strip() for line in status.splitlines() if ':' in line}
    stat = Path(f"/proc/{pid}/stat").read_text().rsplit(')', 1)[1].split()
    return {"monotonic": time.monotonic(), "rss_kib": int(fields['VmRSS'].split()[0]),
            "fds": len(list(Path(f"/proc/{pid}/fd").iterdir())), "threads": int(fields['Threads']),
            "cpu_seconds": (int(stat[11]) + int(stat[12])) / os.sysconf('SC_CLK_TCK')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--node-address', choices=['127.0.0.1','::1','localhost'], default='127.0.0.1')
    parser.add_argument('--entry-family', choices=['both','ipv4','ipv6'], default='both')
    parser.add_argument('--raw-probe-bytes', type=int, default=0, help='diagnostic tiny raw-TCP round trip before TLS workloads')
    parser.add_argument('--handoff', action='store_true', help='use isolated LINE and LANDING server processes')
    parser.add_argument('--quiet-client', action='store_true', help='warn-level client logs for like-for-like timing runs')
    parser.add_argument('--quiet-seconds', type=float, default=65)
    parser.add_argument('--implementation', choices=['rust-current', 'rust-baseline', 'xray'], default='rust-current')
    parser.add_argument('--direct', action='store_true', help='diagnostic origin-only control; not proxy acceptance')
    parser.add_argument('--seconds', type=float, default=3600)
    parser.add_argument('--binary', type=Path, default=ROOT / 'target/release/rust-reality-client')
    parser.add_argument('--output', type=Path, default=ROOT / 'target/application-soak')
    args = parser.parse_args()
    if args.seconds < 10:
        parser.error('use at least 10 real seconds')
    args.output.mkdir(parents=True, exist_ok=True)
    processes, servers, logs = [], [], []
    stop = threading.Event()
    samples, latencies = [], []
    result = {"requested_seconds": args.seconds, "origin_only_control": args.direct, "implementation": args.implementation, "handoff": args.handoff, "node_address": args.node_address, "entry_family": args.entry_family, "quiet_seconds": args.quiet_seconds, "quiet_client": args.quiet_client, "passed": False, "websockets": "15.0.1",
              "upstream_commit": "e3fc3dc36b931baec042074d6c88e928caf6941f",
              "binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
              "workloads": {}, "limitations": ["no packet-loss/netem or real NAT impairment", "no production credentials or AI provider traffic"]}
    try:
        node_log = open(args.output / 'node.log', 'w'); logs.append(node_log)
        # Fresh fixture certificates for long opt-in runs (the fixture default is
        # one day; three days is not sufficient for a 72h test plus setup).
        env = dict(os.environ)
        env['INTEROP_HANDOFF'] = '1' if args.handoff else '0'
        env['INTEROP_ENTRY_FAMILY'] = args.entry_family
        env['INTEROP_OUTPUT_DIR'] = str((args.output / 'fixture').resolve())
        env['INTEROP_TLS_DAYS'] = str(max(2, int(args.seconds // 86400) + 2))
        node = subprocess.Popen(['bash', str(ROOT / 'scripts/interop/upstream-server.sh')], cwd=ROOT, env=env, stdout=node_log, stderr=subprocess.STDOUT)
        processes.append(node)
        deadline = time.monotonic() + 60
        entry_address = {'both':'0.0.0.0:14443','ipv4':'127.0.0.1:14443','ipv6':'[::1]:14443'}[args.entry_family]
        while True:
            if node.poll() is not None:
                raise RuntimeError('isolated upstream failed; inspect node.log')
            if ('"address":"'+entry_address+'"') in (args.output / 'node.log').read_text():
                break
            if time.monotonic() > deadline: raise TimeoutError('upstream startup')
            time.sleep(.1)
        values = dict(line.split('=', 1) for line in (args.output / 'fixture/handoff.env').read_text().splitlines())
        http_port, socks_port = free_port(), free_port()
        config = args.output / 'client.toml'
        config.write_text(f'''[listen]\nsocks5 = "127.0.0.1:{socks_port}"\nhttp = "127.0.0.1:{http_port}"\n[[node]]\nname = "isolated-entry"\naddress = "{args.node_address}"\nport = 14443\nuserId = "{values['RRC_INTEROP_USER_ID']}"\n[node.reality]\npublicKey = "{values['RRC_INTEROP_PUBLIC_KEY']}"\nshortId = "{values['RRC_INTEROP_SHORT_ID']}"\nserverName = "localhost"\n''')
        client_log = open(args.output / 'client.log', 'w'); logs.append(client_log)
        if args.implementation == 'xray':
            config = args.output / 'xray.json'
            config.write_text(json.dumps({"log": {"loglevel": "warning"}, "inbounds": [
                {"listen": "127.0.0.1", "port": socks_port, "protocol": "socks", "settings": {"auth": "noauth", "udp": False}},
                {"listen": "127.0.0.1", "port": http_port, "protocol": "http", "settings": {}}
            ], "outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": args.node_address, "port": 14443,
                "users": [{"id": values['RRC_INTEROP_USER_ID'], "encryption": "none", "flow": "xtls-rprx-vision"}]}]},
                "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
                    "serverName": "localhost", "fingerprint": "chrome", "publicKey": values['RRC_INTEROP_PUBLIC_KEY'], "shortId": values['RRC_INTEROP_SHORT_ID']}}}]}))
            command = [str(args.binary.resolve()), 'run', '-config', str(config.resolve())]
        else:
            command = [str(args.binary.resolve()), 'run', '--config', str(config.resolve()), '--log-level', 'warn' if args.quiet_client else 'debug']
        client = subprocess.Popen(command, stdout=client_log, stderr=subprocess.STDOUT)
        processes.append(client)
        for _ in range(100):
            if client.poll() is not None: raise RuntimeError('client startup failed')
            try:
                with socket.create_connection(('127.0.0.1', http_port), timeout=.1): break
            except OSError: time.sleep(.05)
        if args.raw_probe_bytes:
            with (socket.create_connection(('127.0.0.1', 14444), 15) if args.direct else tunnel(socks_port, 14444, 'socks')) as raw:
                raw.settimeout(3)
                payload = b'x' * args.raw_probe_bytes
                raw.sendall(payload)
                assert recv_exact(raw, len(payload)) == payload
                result['raw_probe_bytes'] = len(payload)
        folder = args.output / 'fixture/tls'
        versions = [('tls13', ssl.TLSVersion.TLSv1_3), ('tls12', ssl.TLSVersion.TLSv1_2)]
        result['pipelining'] = []
        if not args.direct:
            for label, version in versions:
                target = int(values['RRC_INTEROP_' + label.upper()].rsplit(':', 1)[1])
                for kind, port in [('http', http_port), ('socks', socks_port)]:
                    proof = pipelined_tls(port, target, kind, tls_context(folder, version))
                    proof.update(inbound=kind)
                    result['pipelining'].append(proof)

        started = time.monotonic()
        until = started + args.seconds
        endpoints = []
        for label, version in versions:
            sse = SSEServer(('127.0.0.1', 0), SSE)
            sse.context = tls_context(folder, version, True)
            sse.deadline = until
            servers.append(sse)
            threading.Thread(target=sse.serve_forever, daemon=True).start()
            endpoints.append((label, version, 0, sse.server_address[1]))

        async def wss(kind, proxy, endpoint, short=False):
            label, version, port, _ = endpoint
            began = time.monotonic()
            async with connect(f'wss://localhost:{port}/echo', sock=(socket.create_connection(('127.0.0.1', port), 15) if args.direct else tunnel(proxy, port, kind)), ssl=tls_context(folder, version), proxy=None, ping_interval=None, compression=None, close_timeout=5) as ws:
                assert ws.transport.get_extra_info('ssl_object').version() == ('TLSv1.3' if label == 'tls13' else 'TLSv1.2')
                n = 0
                while time.monotonic() < until:
                    size = 65536 if n % 5 == 0 else 128
                    payload = struct.pack('!Q', n) + hashlib.sha256(str(n).encode()).digest() * (size // 32)
                    sent = time.monotonic()
                    await ws.send([payload[:17], payload[17:]]) # real WebSocket fragmentation
                    assert await asyncio.wait_for(ws.recv(), 15) == payload, 'loss, duplication, reordering or corruption'
                    latencies.append(time.monotonic() - sent)
                    pong = await ws.ping(struct.pack('!Q', n))
                    await asyncio.wait_for(pong, 10)
                    n += 1
                    if short:
                        await ws.close(code=1000)
                        assert ws.close_code == 1000, "incomplete WebSocket Close exchange"
                        return n
                    # App-level quiet > keepalive window on long runs. Native TCP
                    # probes remain enabled; no proxy-generated WebSocket pings.
                    quiet = min(args.quiet_seconds if n % 10 == 0 else .1, max(0, until - time.monotonic()))
                    await asyncio.sleep(quiet)
                await ws.close(code=1000)
                assert ws.close_code == 1000, "incomplete WebSocket Close exchange"
                return {"messages": n, "wall_seconds": time.monotonic() - began, "close_code": ws.close_code}

        def sse(kind, proxy, endpoint):
            label, version, _, port = endpoint
            with tls_context(folder, version).wrap_socket(socket.create_connection(('127.0.0.1', port), 15) if args.direct else tunnel(proxy, port, kind), server_hostname='localhost') as sock:
                sock.sendall(b'GET /events HTTP/1.1\r\nHost: localhost\r\n\r\n')
                with sock.makefile('rb') as stream:
                    assert stream.readline().startswith(b'HTTP/1.1 200')
                    while stream.readline() != b'\r\n': pass
                    sequence = 0
                    while True:
                        line = stream.readline()
                        if not line: break
                        assert line == f'id: {sequence}\n'.encode()
                        assert stream.readline() == f'data: {hashlib.sha256(str(sequence).encode()).hexdigest()}\n'.encode()
                        assert stream.readline() == b'\n'
                        sequence += 1
                        if sequence % 20 == 0: stop.wait(.5) # bounded slow reader
                    assert time.monotonic() >= until, 'SSE ended before workload deadline'
                    return {"events": sequence}

        async def churn():
            count = 0
            while time.monotonic() < until:
                await wss('http' if count % 2 == 0 else 'socks', http_port if count % 2 == 0 else socks_port, endpoints[count % 2], True)
                count += 1
                await asyncio.sleep(.5)
            return count

        def sample():
            while not stop.is_set():
                samples.append(sample_process(client.pid))
                stop.wait(5)

        sampler = threading.Thread(target=sample, daemon=True); sampler.start()
        async def workloads():
            ws_servers = []
            tasks = []
            try:
                for i, (label, version, _, sse_port) in enumerate(endpoints):
                    ws = await serve(ws_origin, '127.0.0.1', 0, ssl=tls_context(folder, version, True), ping_interval=None, compression=None, max_size=2**20)
                    ws_servers.append(ws)
                    endpoints[i] = (label, version, ws.sockets[0].getsockname()[1], sse_port)
                async def record(name, operation):
                    result['workloads'][name] = await operation
                    print(json.dumps({"finished": name, "result": result['workloads'][name]}), flush=True)
                for endpoint in endpoints:
                    for kind, proxy in [('http', http_port), ('socks', socks_port)]:
                        tasks.append(asyncio.create_task(record(f'wss-{kind}-{endpoint[0]}', wss(kind, proxy, endpoint))))
                        tasks.append(asyncio.create_task(record(f'sse-{kind}-{endpoint[0]}', asyncio.to_thread(sse, kind, proxy, endpoint))))
                tasks.append(asyncio.create_task(record('churn', churn())))
                await asyncio.gather(*tasks)
            finally:
                for task in tasks: task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                for server in ws_servers:
                    server.close()
                    await server.wait_closed()
        asyncio.run(workloads())
        result['wall_seconds'] = time.monotonic() - started
        stop.set(); sampler.join(10)
        time.sleep(1)
        result['after_drain'] = sample_process(client.pid)
        client.send_signal(signal.SIGINT); client.wait(15)
        assert client.returncode == 0
        events = []
        for line in (args.output / 'client.log').read_text().splitlines():
            try: events.append(json.loads(line))
            except json.JSONDecodeError: pass
        sessions = [e for e in events if e.get('event') == 'sessionFinished']
        modes = {e.get('downlink') for e in sessions}
        server_modes = set()
        handoff_sessions = 0
        for line in (args.output / 'node.log').read_text().splitlines():
            try: event = json.loads(line)
            except json.JSONDecodeError: continue
            if event.get('event') == 'connection_completed' and 'handoff_server_sequence' in event:
                handoff_sessions += 1
            if event.get('event') == 'connection_completed' and 'downlink_direct' in event:
                server_modes.add('direct' if event['downlink_direct'] else 'non-direct')
        if args.handoff:
            assert handoff_sessions > 0, 'no evidence of the LANDING path'
        else:
            assert args.direct or {'direct', 'non-direct'} <= server_modes, f'missing server transitions: {server_modes}'
        result['handoff_sessions'] = handoff_sessions
        if args.implementation == 'rust-current' and not args.direct and not args.quiet_client:
            assert {'direct', 'outer'} <= modes, f'missing client transitions: {modes}'
        result['server_modes'] = sorted(server_modes)
        result['observed_downlinks'] = sorted(modes)
        result['session_completions'] = len(sessions)
        resources = [e for e in events if e.get('event') == 'resources']
        result['resources'] = resources
        if resources:
            assert resources[-1]['active'] == 0, 'tracked tasks did not drain'
            assert resources[-1]['connectionsAvailable'] == 256, 'connection permits leaked'
            assert resources[-1]['handshakesAvailable'] == 32, 'handshake permits leaked'
            assert resources[-1]['probesAvailable'] == 4 and resources[-1]['sparesAvailable'] == 16
            assert resources[-1]['panicked'] == 0

        result['samples'] = samples
        times = sorted(latencies)
        result['roundtrip_samples'] = len(times)
        result['roundtrip_seconds'] = latencies
        result['roundtrip_p50_ms'] = times[len(times)//2] * 1000
        result['roundtrip_p95_ms'] = times[min(len(times)-1, int(len(times)*.95))] * 1000
        result['roundtrip_p99_ms'] = times[min(len(times)-1, int(len(times)*.99))] * 1000
        result['passed'] = True
    except BaseException as exc:
        result['error'] = f'{type(exc).__name__}: {exc}'
        raise
    finally:
        stop.set()
        for server in servers:
            server.shutdown()
        for process in reversed(processes):
            if process.poll() is None:
                process.send_signal(signal.SIGINT)
                try: process.wait(15)
                except subprocess.TimeoutExpired: process.kill(); process.wait()
        for log in logs: log.close()
        (args.output / 'report.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps({"passed": result['passed'], "report": str(args.output / 'report.json')}), flush=True)

if __name__ == '__main__':
    main()
