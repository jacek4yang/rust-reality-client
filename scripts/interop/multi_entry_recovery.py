#!/usr/bin/env python3
"""Two real entry processes, one unchanged LANDING, explicit new-session recovery.

A stopped entry induces an authentication stall; a killed entry terminates its
existing tunnel. The client must establish new sessions on the surviving entry
without replaying or migrating the killed tunnel. Isolated loopback only.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import time

from application_soak import ROOT, free_port, recv_exact, tunnel
from resource_adversity import events, wait_until


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'target/release/rust-reality-client')
    parser.add_argument('--output', type=Path, default=ROOT / 'target/multi-entry-recovery')
    args = parser.parse_args()
    out = args.output.resolve(); out.mkdir(parents=True, exist_ok=True)
    report = {'passed': False, 'started_utc': datetime.now(timezone.utc).isoformat(),
              'binary_sha256': hashlib.sha256(args.binary.read_bytes()).hexdigest(),
              'upstream_commit': 'e3fc3dc36b931baec042074d6c88e928caf6941f',
              'shared_landing': True, 'rounds': []}
    processes, logs, sockets = [], [], []
    entry_a = None
    try:
        upstream = os.environ['INTEROP_BINARY']
        env = dict(os.environ, INTEROP_OUTPUT_DIR=str(out/'fixture'), INTEROP_HANDOFF='1')
        log = (out/'node.log').open('w'); logs.append(log)
        fixture = subprocess.Popen(['bash', str(ROOT/'scripts/interop/upstream-server.sh')], cwd=ROOT,
                                   env=env, stdout=log, stderr=subprocess.STDOUT)
        processes.append(fixture)
        def ready():
            assert fixture.poll() is None, 'fixture failed'
            return '"address":"0.0.0.0:14443"' in (out/'node.log').read_text()
        wait_until(ready,60)
        entry_a = int((out/'fixture/entry.pid').read_text())
        values = dict(line.split('=',1) for line in (out/'fixture/handoff.env').read_text().splitlines())
        port_b = free_port()
        b_config = json.loads((out/'fixture/server.json').read_text())
        b_config['listeners'] = [{'port':port_b, 'ip':'ipv4Only','ipv4':'127.0.0.1'}]
        (out/'entry-b.json').write_text(json.dumps(b_config))
        http,socks=free_port(),free_port()
        config=f'[listen]\nsocks5 = "127.0.0.1:{socks}"\nhttp = "127.0.0.1:{http}"\n'
        for name,port in [('entry-a',14443),('entry-b',port_b)]:
            config+=f'''[[node]]\nname = "{name}"\naddress = "127.0.0.1"\nport = {port}\nuserId = "{values['RRC_INTEROP_USER_ID']}"\n[node.reality]\npublicKey = "{values['RRC_INTEROP_PUBLIC_KEY']}"\nshortId = "{values['RRC_INTEROP_SHORT_ID']}"\nserverName = "localhost"\n'''
        (out/'client.toml').write_text(config)
        client_log=(out/'client.log').open('w');logs.append(client_log)
        client=subprocess.Popen([str(args.binary.resolve()),'run','--config',str(out/'client.toml'),'--log-level','debug'],stdout=client_log,stderr=subprocess.STDOUT)
        processes.append(client)
        def listening():
            assert client.poll() is None
            try:
                with socket.create_connection(('127.0.0.1',http),.1):return True
            except OSError:return False
        wait_until(listening)
        payload=bytes(range(256))*16
        def exchange(sock):
            sock.sendall(payload)
            assert recv_exact(sock,len(payload))==payload, 'payload corrupted or replayed'
        # B has never listened, so this established stream must use A.
        survivor=tunnel(http,14444,'http');sockets.append(survivor);exchange(survivor)
        for index in range(3):
            b_log=(out/f'entry-b-{index}.log').open('w');logs.append(b_log)
            b=subprocess.Popen([upstream,'run','--config',str(out/'entry-b.json')],stdout=b_log,stderr=subprocess.STDOUT)
            processes.append(b)
            def b_ready():
                assert b.poll() is None
                return f'"address":"127.0.0.1:{port_b}"' in (out/f'entry-b-{index}.log').read_text()
            wait_until(b_ready)
            os.kill(entry_a,signal.SIGSTOP)
            began=time.monotonic()
            # A cannot authenticate while suspended. A successful complete
            # application round trip therefore independently proves B carried it.
            doomed=tunnel(socks,14444,'socks');sockets.append(doomed);exchange(doomed)
            row={'round':index,'stalled_entry_fallback_seconds':time.monotonic()-began}
            assert row['stalled_entry_fallback_seconds']<15
            os.kill(entry_a,signal.SIGCONT)
            began=time.monotonic()
            b.kill();b.wait(5)
            doomed.settimeout(10)
            try:
                received=doomed.recv(1)
                assert received==b'', 'killed tunnel emitted unexpected data'
            except (ConnectionResetError,ConnectionAbortedError):
                pass
            row['killed_tunnel_terminal_seconds']=time.monotonic()-began
            doomed.close();sockets.remove(doomed)
            exchange(survivor)
            timings=[]
            for n in range(100):
                began=time.monotonic()
                kind,port=('http',http) if n%2==0 else ('socks',socks)
                with tunnel(port,14444,kind) as sock:exchange(sock)
                timings.append(time.monotonic()-began)
            row['new_sessions']=len(timings)
            row['new_session_max_seconds']=max(timings)
            row['original_surviving_stream_intact']=True
            report['rounds'].append(row)
            print(json.dumps(row),flush=True)
        survivor.close();sockets.remove(survivor)
        time.sleep(1)
        client.send_signal(signal.SIGINT);client.wait(15)
        assert client.returncode==0
        resources=[e for e in events(out/'client.log') if e.get('event')=='resources']
        final=resources[-1];report['final_resources']=final
        assert final['active']==0 and final['panicked']==0
        for key,value in [('connectionsAvailable',256),('handshakesAvailable',32),('probesAvailable',4),('sparesAvailable',16)]:
            assert final[key]==value
        report['passed']=True
    except BaseException as exc:
        report['error']=f'{type(exc).__name__}: {exc}'
        raise
    finally:
        if entry_a:
            try:os.kill(entry_a,signal.SIGCONT)
            except ProcessLookupError:pass
        for sock in sockets:sock.close()
        for proc in reversed(processes):
            if proc.poll() is None:
                proc.send_signal(signal.SIGINT)
                try:proc.wait(15)
                except subprocess.TimeoutExpired:proc.kill();proc.wait()
        for log in logs:log.close()
        report['finished_utc']=datetime.now(timezone.utc).isoformat()
        (out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps({'passed':report['passed'],'report':str(out/'report.json')}),flush=True)


if __name__=='__main__':main()
