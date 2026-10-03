#!/usr/bin/env python3
"""Controlled bulk/CPU profile with real TLS and fixed unmodified upstream.

The origin-only arm is a fixture control, NOT an upper bound or a hardware/WAN
theoretical limit. Proxy buffering can change scheduling and aggregation. Python TLS/hash processing and a shared host may dominate.
Run throughput trials without strace; --trace measures syscall shape separately.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import socketserver
import ssl
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/interop'))
from application_soak import free_port, recv_exact, sample_process, tls_context, tunnel

BLOCK = bytes(range(256)) * 256


class Origin(socketserver.BaseRequestHandler):
    def handle(self):
        with self.server.context.wrap_socket(self.request, server_side=True) as conn:
            head = recv_exact(conn, 9)
            count = int.from_bytes(head[1:], 'big')
            assert 0 < count <= 1024 * 1024 * 1024
            digest = hashlib.sha256()
            left = count
            while left:
                if head[:1] == b'D':
                    data = BLOCK[:min(left, len(BLOCK))]
                    conn.sendall(data)
                else:
                    assert head[:1] == b'U'
                    data = conn.recv(min(left, len(BLOCK)))
                    if not data: raise EOFError('upload truncated')
                digest.update(data)
                left -= len(data)
            conn.sendall(digest.digest())


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def run_transfer(port, proxy, context, direction, size, expected, barrier):
    barrier.wait(timeout=20)
    begin = time.monotonic()
    raw = socket.create_connection(('127.0.0.1', port), 30) if proxy is None else tunnel(proxy, port, 'socks')
    with context.wrap_socket(raw, server_hostname='localhost') as conn:
        conn.settimeout(60)
        setup = time.monotonic()-begin
        begin = time.monotonic()
        conn.sendall(direction.encode() + size.to_bytes(8, 'big'))
        left = size
        digest = hashlib.sha256()
        while left:
            if direction == 'U':
                data = BLOCK[:min(left, len(BLOCK))]
                conn.sendall(data)
            else:
                data = conn.recv(min(left, len(BLOCK)))
                if not data: raise EOFError('download truncated')
            digest.update(data)
            left -= len(data)
        assert digest.digest() == expected
        assert recv_exact(conn, 32) == expected
        return {'setup_seconds': setup, 'transfer_seconds': time.monotonic()-begin, 'verified_bytes': size}


def config_for(label, port, values, output):
    if label == 'xray':
        path = output/'xray.json'
        path.write_text(json.dumps({'log':{'loglevel':'warning'},'inbounds':[{'listen':'127.0.0.1','port':port,'protocol':'socks','settings':{'auth':'noauth','udp':False}}], 'outbounds':[{'protocol':'vless','settings':{'vnext':[{'address':'127.0.0.1','port':14443,'users':[{'id':values['RRC_INTEROP_USER_ID'],'encryption':'none','flow':'xtls-rprx-vision'}]}]},'streamSettings':{'network':'tcp','security':'reality','realitySettings':{'serverName':'localhost','fingerprint':'chrome','publicKey':values['RRC_INTEROP_PUBLIC_KEY'],'shortId':values['RRC_INTEROP_SHORT_ID']}}}]}))
        return ['run','-config',str(path)]
    path = output/'client.toml'
    path.write_text(f'''[listen]\nsocks5="127.0.0.1:{port}"\nhttp=""\n[[node]]\nname="fixture"\naddress="127.0.0.1"\nport=14443\nuserId="{values['RRC_INTEROP_USER_ID']}"\n[node.reality]\npublicKey="{values['RRC_INTEROP_PUBLIC_KEY']}"\nshortId="{values['RRC_INTEROP_SHORT_ID']}"\nserverName="localhost"\n''')
    return ['run','--config',str(path),'--log-level','warn']


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--current',type=Path,required=True)
    p.add_argument('--candidate',type=Path)
    p.add_argument('--xray',type=Path,required=True)
    p.add_argument('--mib',type=int,default=32)
    p.add_argument('--rounds',type=int,default=2)
    p.add_argument('--trace',action='store_true')
    p.add_argument('--context',required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();a.output=a.output.resolve();a.output.mkdir(parents=True,exist_ok=True)
    assert 1 <= a.mib <= 1024 and a.rounds > 0
    size=a.mib*1024*1024
    digest=hashlib.sha256()
    for _ in range(size//len(BLOCK)):digest.update(BLOCK)
    expected=digest.digest()
    binaries={'current':a.current.resolve(),'xray':a.xray.resolve()}
    if a.candidate:binaries['candidate']=a.candidate.resolve()
    report={'context':a.context,'trace':a.trace,'passed':False,'upstream_commit':'e3fc3dc36b931baec042074d6c88e928caf6941f','binary_sha256':{k:hashlib.sha256(v.read_bytes()).hexdigest() for k,v in binaries.items()},'trials':[], 'limitations':['shared-host loopback, not WAN','Python TLS and hashing affect the fixture; direct is not an upper bound','traced timing is diagnostic only','no authenticated production traffic']}
    nodes=[];origins=[]
    try:
        log=open(a.output/'node.log','w');nodes.append(log)
        node=subprocess.Popen(['bash',str(ROOT/'scripts/interop/upstream-server.sh')],env=dict(os.environ,INTEROP_OUTPUT_DIR=str(a.output/'fixture')),stdout=log,stderr=subprocess.STDOUT)
        nodes.append(node)
        for _ in range(120):
            if 'listener_started' in (a.output/'node.log').read_text():break
            if node.poll() is not None:raise RuntimeError('server startup')
            time.sleep(.5)
        else:raise TimeoutError('server startup')
        values=dict(line.split('=',1) for line in (a.output/'fixture/handoff.env').read_text().splitlines())
        folder=a.output/'fixture/tls'
        for name,version in [('tls13',ssl.TLSVersion.TLSv1_3),('tls12',ssl.TLSVersion.TLSv1_2)]:
            origin=Server(('127.0.0.1',0),Origin);origin.context=tls_context(folder,version,True)
            threading.Thread(target=origin.serve_forever,daemon=True).start()
            origins.append((name,version,origin))
        order=['direct']+list(binaries)
        for repetition in range(a.rounds):
            for label in (order if repetition%2==0 else list(reversed(order))):
                out=a.output/f'{repetition}-{label}';out.mkdir(exist_ok=True)
                proc=tracer=None;port=None;samples=[];stop=threading.Event();sampler=None
                with open(out/'client.log','w') as client_log:
                    try:
                        if label!='direct':
                            port=free_port();command=[str(binaries[label])]+config_for(label,port,values,out)
                            if a.trace:command=['strace','-f','-c','-o',str(out/'syscalls.txt')]+command
                            proc=subprocess.Popen(command,stdout=client_log,stderr=subprocess.STDOUT)
                            pid=proc.pid
                            if a.trace:
                                tracer=proc
                                for _ in range(100):
                                    if proc.poll() is not None:
                                        raise RuntimeError('strace exited; verify ptrace availability, do not infer a client defect')
                                    child_path=Path(f'/proc/{proc.pid}/task/{proc.pid}/children')
                                    children=child_path.read_text().split() if child_path.exists() else []
                                    if children:pid=int(children[0]);break
                                    time.sleep(.02)
                            for _ in range(100):
                                if proc.poll() is not None:raise RuntimeError('client startup')
                                try:
                                    with socket.create_connection(('127.0.0.1',port),.1):break
                                except OSError:time.sleep(.05)
                            def sample():
                                while not stop.wait(.1):samples.append(sample_process(pid))
                            sampler=threading.Thread(target=sample);sampler.start()
                        for name,version,origin in origins:
                            for concurrency in [1,4]:
                                for direction in ['D','U']:
                                    before=sample_process(pid) if proc else None
                                    barrier=threading.Barrier(concurrency+1)
                                    with ThreadPoolExecutor(max_workers=concurrency) as pool:
                                        jobs=[pool.submit(run_transfer,origin.server_address[1],port,tls_context(folder,version),direction,size,expected,barrier) for _ in range(concurrency)]
                                        start=time.monotonic();barrier.wait(timeout=20)
                                        results=[job.result(timeout=90) for job in jobs]
                                        wall=time.monotonic()-start
                                    after=sample_process(pid) if proc else None
                                    trial={'round':repetition+1,'label':label,'tls':name,'direction':direction,'concurrency':concurrency,'mib':a.mib*concurrency,'wall_seconds':wall,'mib_per_second':a.mib*concurrency/wall,'transfers':results,'client_cpu_seconds':after['cpu_seconds']-before['cpu_seconds'] if proc else None,'client_rss_kib':after['rss_kib'] if proc else None,'client_fds':after['fds'] if proc else None}
                                    report['trials'].append(trial);print(json.dumps({k:trial[k] for k in ['round','label','tls','direction','concurrency','mib_per_second','client_cpu_seconds']}),flush=True)
                        report.setdefault('samples',{})[f'{repetition}-{label}']=samples
                    finally:
                        stop.set()
                        if sampler:sampler.join(5)
                        if proc and proc.poll() is None:
                            os.kill(pid,signal.SIGINT)
                            try:proc.wait(15)
                            except subprocess.TimeoutExpired:proc.kill();proc.wait()
                        for filename in ['client.toml','xray.json']:(out/filename).unlink(missing_ok=True)
        report['passed']=True
    finally:
        (a.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
        for _,_,origin in origins:origin.shutdown();origin.server_close()
        for node in reversed(nodes):
            if isinstance(node,subprocess.Popen):
                node.terminate()
                try:node.wait(10)
                except subprocess.TimeoutExpired:node.kill();node.wait()
            else:node.close()

if __name__=='__main__':main()
