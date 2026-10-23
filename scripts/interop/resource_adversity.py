#!/usr/bin/env python3
"""Real-process admission, malformed-input, descriptor-exhaustion and stop tests.

Only isolated loopback fixtures are used. RLIMIT_NOFILE applies exclusively to
our child client, never to the host or the user's configuration. All generated
credentials remain under target/. Run with the same venv as application_soak.py.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import socket
import subprocess
import time

from application_soak import ROOT, free_port, recv_exact, sample_process, tunnel


def wait_until(check, seconds=20):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(.05)
    raise AssertionError('condition did not become true before deadline')


def events(path):
    result = []
    for line in path.read_text().splitlines():
        try:
            result.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'target/release/rust-reality-client')
    parser.add_argument('--output', type=Path, default=ROOT / 'target/resource-adversity')
    args = parser.parse_args()
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    assert hard >= 4096, 'test controller needs capacity for >1024 test sockets'
    resource.setrlimit(resource.RLIMIT_NOFILE, (max(4096, soft), hard))
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    report = {'passed': False, 'started_utc': datetime.now(timezone.utc).isoformat(),
              'binary_sha256': hashlib.sha256(args.binary.read_bytes()).hexdigest(),
              'upstream_commit': 'e3fc3dc36b931baec042074d6c88e928caf6941f', 'cases': {}}
    processes, logs, sockets = [], [], []
    try:
        env = dict(os.environ, INTEROP_OUTPUT_DIR=str(out / 'fixture'))
        node_log = (out / 'node.log').open('w'); logs.append(node_log)
        node = subprocess.Popen(['bash', str(ROOT / 'scripts/interop/upstream-server.sh')],
                                cwd=ROOT, env=env, stdout=node_log, stderr=subprocess.STDOUT)
        processes.append(node)
        def ready():
            assert node.poll() is None, 'fixture failed'
            return '"address":"0.0.0.0:14443"' in (out / 'node.log').read_text()
        wait_until(ready, 60)
        values = dict(line.split('=', 1) for line in (out / 'fixture/handoff.env').read_text().splitlines())

        for name, nofile in [('normal', None), ('descriptor-pressure', 128)]:
            http, socks = free_port(), free_port()
            config = out / f'{name}.toml'
            config.write_text(f'''[listen]\nsocks5 = "127.0.0.1:{socks}"\nhttp = "127.0.0.1:{http}"\n[[node]]\nname = "test-entry"\naddress = "127.0.0.1"\nport = 14443\nuserId = "{values['RRC_INTEROP_USER_ID']}"\n[node.reality]\npublicKey = "{values['RRC_INTEROP_PUBLIC_KEY']}"\nshortId = "{values['RRC_INTEROP_SHORT_ID']}"\nserverName = "localhost"\n''')
            logpath = out / f'{name}.log'
            log = logpath.open('w'); logs.append(log)
            def child_limits():
                if nofile:
                    resource.setrlimit(resource.RLIMIT_NOFILE, (nofile, nofile))
            client = subprocess.Popen([str(args.binary.resolve()), 'run', '--config', str(config), '--log-level', 'debug'],
                                      stdout=log, stderr=subprocess.STDOUT, preexec_fn=child_limits)
            processes.append(client)
            def listening():
                assert client.poll() is None, 'client died'
                try:
                    with socket.create_connection(('127.0.0.1', http), .1):
                        return True
                except OSError:
                    return False
            wait_until(listening)
            baseline = sample_process(client.pid)
            stable = tunnel(http, 14444, 'http'); sockets.append(stable)
            marker = bytes(range(256)) * 16
            def echo():
                stable.sendall(marker)
                assert recv_exact(stable, len(marker)) == marker
            echo()
            case = {'baseline': baseline}
            report['cases'][name] = case
            if nofile is None:
                # Every invalid input must receive its expected local refusal;
                # no upstream availability can make these assertions pass.
                corpus = [
                    (http, b'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n', b'HTTP/1.1 405'),
                    (http, b'CONNECT localhost:80 HTTP/2.0\r\n\r\n', b'HTTP/1.1 505'),
                    (http, b'CONNECT localhost:0 HTTP/1.1\r\n\r\n', b'HTTP/1.1 400'),
                    (http, b'CONNECT localhost:80 HTTP/1.1\r\nX: ' + b'x' * 9000, b'HTTP/1.1 431'),
                    (socks, b'\x05\x01\x02', b'\x05\xff'),
                ]
                def malformed(index):
                    port, payload, expected = corpus[index % len(corpus)]
                    with socket.create_connection(('127.0.0.1', port), 5) as sock:
                        sock.sendall(payload)
                        assert recv_exact(sock, len(expected)) == expected, index
                with ThreadPoolExecutor(max_workers=24) as pool:
                    list(pool.map(malformed, range(1000)))
                echo()
                case['malformed_refusals'] = 1000
                def slow_head(port, prefix):
                    with socket.create_connection(('127.0.0.1', port), 20) as sock:
                        began = time.monotonic()
                        sock.sendall(prefix)
                        assert sock.recv(1) == b'', 'unfinished head was accepted'
                        elapsed = time.monotonic() - began
                        assert 14 <= elapsed < 18, elapsed
                        return elapsed
                with ThreadPoolExecutor(max_workers=2) as pool:
                    deadlines = [pool.submit(slow_head, http, b'CON'),
                                 pool.submit(slow_head, socks, b'\x05')]
                    case['unfinished_head_seconds'] = [job.result() for job in deadlines]
                echo()
                # Exhaust connection admission without creating 1000
                # upstream authentications. Existing payload must keep flowing.
                parked = []
                for i in range(1150):
                    try:
                        # HTTP takes a 256-slot connection permit before reading
                        # the head; excess clients must be rejected promptly.
                        parked.append(socket.create_connection(('127.0.0.1', http), 5))
                        if i % 32 == 0:
                            time.sleep(.01)
                    except OSError as exc:
                        case['controller_connect_error'] = repr(exc)
                        break
                sockets.extend(parked)
                time.sleep(.3)
                case['parked_attempts_connected'] = len(parked)
                case['pressure'] = sample_process(client.pid)
                assert len(parked) >= 1024, 'insufficient admission pressure'
                assert 256 <= case['pressure']['fds'] <= baseline['fds'] + 280
                assert case['pressure']['rss_kib'] < 128 * 1024
                echo()
            else:
                parked = []
                for _ in range(300):
                    try:
                        parked.append(socket.create_connection(('127.0.0.1', http), .1))
                    except OSError:
                        break
                sockets.extend(parked)
                time.sleep(2)
                case['pressure'] = sample_process(client.pid)
                assert case['pressure']['fds'] >= 120, 'descriptor limit was not reached'
                assert any(e.get('event') == 'acceptFailed' and
                           '(os error 24)' in e.get('reason', '') for e in events(logpath)), 'no observed EMFILE'
                echo()
                before = sample_process(client.pid)
                time.sleep(2)
                after = sample_process(client.pid)
                case['pressure_cpu_seconds'] = after['cpu_seconds'] - before['cpu_seconds']
                assert case['pressure_cpu_seconds'] < 1, 'accept loop spins under EMFILE'
            for sock in parked:
                sock.close(); sockets.remove(sock)
            wait_until(lambda: sample_process(client.pid)['fds'] <= baseline['fds'] + 8)
            # New connections work after exhaustion, without restarting client.
            for kind, port in [('http', http), ('socks', socks)]:
                with tunnel(port, 14444, kind) as sock:
                    sock.sendall(marker)
                    assert recv_exact(sock, len(marker)) == marker
            echo()
            case['recovered'] = sample_process(client.pid)
            # Keep an established connection open past the stop request. The
            # documented grace expires, counts cancellation and releases slots.
            began = time.monotonic()
            client.send_signal(signal.SIGTERM)
            client.wait(timeout=14)
            case['stop_seconds'] = time.monotonic() - began
            assert client.returncode == 0, client.returncode
            assert 9 <= case['stop_seconds'] < 13, case
            stable.close(); sockets.remove(stable)
            resources = [e for e in events(logpath) if e.get('event') == 'resources']
            assert resources, 'no final resource report'
            final = resources[-1]
            assert final['active'] == 0 and final['panicked'] == 0, final
            assert final['cancelled'] >= 1, final
            for key, count in [('connectionsAvailable',256), ('handshakesAvailable',32), ('probesAvailable',4), ('sparesAvailable',16)]:
                assert final[key] == count, final
            case['final_resources'] = final
            report['cases'][name] = case
            print(json.dumps({'completed': name, 'result': case}), flush=True)
        report['passed'] = True
    except BaseException as exc:
        report['error'] = f'{type(exc).__name__}: {exc}'
        raise
    finally:
        for sock in sockets:
            sock.close()
        for proc in reversed(processes):
            if proc.poll() is None:
                proc.send_signal(signal.SIGINT)
                try: proc.wait(15)
                except subprocess.TimeoutExpired: proc.kill(); proc.wait()
        for log in logs:
            log.close()
        report['finished_utc'] = datetime.now(timezone.utc).isoformat()
        (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'passed': report['passed'], 'report': str(out / 'report.json')}), flush=True)


if __name__ == '__main__':
    main()
