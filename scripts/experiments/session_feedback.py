#!/usr/bin/env python3
"""Session-quality ablation with an unmodified pinned rust-reality server.

The fast entry path deliberately corrupts an authenticated post-establishment
record. The slower path forwards unchanged. This proves only the bounded
protocol-defect feedback mechanism, not attribution of ordinary resets or
recovery from a shared LANDING outage. No application payload is replayed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import threading
import time
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts/interop'))
from application_soak import tunnel, free_port, recv_exact


class Bridge:
    def __init__(self, delay=0):
        self.delay=delay
        self.listener=socket.socket();self.listener.bind(('127.0.0.1',0));self.listener.listen()
        self.port=self.listener.getsockname()[1]
        self.connections=[]
        self.stopped=False
        threading.Thread(target=self.accept,daemon=True).start()
    def accept(self):
        while not self.stopped:
            try:local,_=self.listener.accept()
            except OSError:return
            remote=socket.create_connection(('127.0.0.1',14443))
            state={'corrupt':False,'corrupted':False,'local':local,'remote':remote}
            self.connections.append(state)
            for source,target,down in [(local,remote,False),(remote,local,True)]:
                threading.Thread(target=self.copy,args=(source,target,down,state),daemon=True).start()
    def copy(self,source,target,down,state):
        try:
            while True:
                data=source.recv(65536)
                if not data:
                    target.shutdown(socket.SHUT_WR);return
                if self.delay:time.sleep(self.delay)
                if down and state['corrupt']:
                    changed=bytearray(data);changed[-1]^=1;data=bytes(changed)
                    state['corrupt']=False;state['corrupted']=True
                target.sendall(data)
        except OSError:pass
    def close(self):
        self.stopped=True;self.listener.close()
        for state in self.connections:
            for key in ['local','remote']:
                try:state[key].shutdown(socket.SHUT_RDWR)
                except OSError:pass
                state[key].close()


def run(binary,out,values):
    out.mkdir(parents=True,exist_ok=True)
    fast,slow=Bridge(),Bridge(.01)
    port=free_port()
    text=f'[listen]\nsocks5="127.0.0.1:{port}"\nhttp=""\n'
    for name,bridge in [('fast-corrupted',fast),('slower-intact',slow)]:
        text+=f'''[[node]]\nname="{name}"\naddress="127.0.0.1"\nport={bridge.port}\nuserId="{values['RRC_INTEROP_USER_ID']}"\n[node.reality]\npublicKey="{values['RRC_INTEROP_PUBLIC_KEY']}"\nshortId="{values['RRC_INTEROP_SHORT_ID']}"\nserverName="localhost"\n'''
    config=out/'client.toml';config.write_text(text)
    rows=[]
    with (out/'client.log').open('w') as log:
        client=subprocess.Popen([str(binary.resolve()),'run','--config',str(config),'--log-level','debug'],stdout=log,stderr=subprocess.STDOUT)
        try:
            for _ in range(100):
                try:
                    with socket.create_connection(('127.0.0.1',port),.2):break
                except OSError:time.sleep(.05)
            # Retained stream proves later route choices don't migrate or kill it.
            old=tunnel(port,14444,'socks');old.sendall(b'old-stream-alive');assert recv_exact(old,len(b'old-stream-alive'))==b'old-stream-alive'
            for sequence in range(12):
                before=len(fast.connections)
                sock=tunnel(port,14444,'socks');sock.settimeout(5)
                chosen_fast=len(fast.connections)>before
                if chosen_fast:fast.connections[-1]['corrupt']=True
                payload=f'sequence-{sequence}'.encode()
                started=time.monotonic()
                try:
                    sock.sendall(payload);received=recv_exact(sock,len(payload))
                    good=received==payload
                except (OSError,EOFError):good=False
                finally:sock.close()
                rows.append({'sequence':sequence,'path':'fast-corrupted' if chosen_fast else 'slower-intact','delivered':good,'elapsed_seconds':time.monotonic()-started})
                time.sleep(.05)
                old.sendall(b'old-stream-alive');assert recv_exact(old,len(b'old-stream-alive'))==b'old-stream-alive','existing stream interrupted by future routing'
            old.close()
        finally:
            client.send_signal(signal.SIGINT)
            try:client.wait(15)
            except subprocess.TimeoutExpired:client.kill();client.wait()
            fast.close();slow.close();config.unlink(missing_ok=True)
    result={'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'requests':rows,'successes':sum(row['delivered'] for row in rows),
            'old_stream_survived':True,'corruptions':sum(state['corrupted'] for state in fast.connections)}
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--current',type=Path,required=True)
    parser.add_argument('--ablated',type=Path,required=True)
    parser.add_argument('--output',type=Path,default=ROOT/'target/session-ablation')
    a=parser.parse_args();a.output=a.output.resolve();a.output.mkdir(parents=True,exist_ok=True)
    env=dict(os.environ,INTEROP_OUTPUT_DIR=str(a.output/'fixture'))
    with (a.output/'node.log').open('w') as log:
        node=subprocess.Popen(['bash',str(ROOT/'scripts/interop/upstream-server.sh')],env=env,stdout=log,stderr=subprocess.STDOUT)
        try:
            for _ in range(120):
                if 'listener_started' in (a.output/'node.log').read_text():break
                if node.poll() is not None:raise RuntimeError('node startup failed')
                time.sleep(.5)
            values=dict(line.split('=',1) for line in (a.output/'fixture/handoff.env').read_text().splitlines())
            results=[]
            # ABBA, repeated twice. Same upstream process/config for all eight runs.
            for i,label in enumerate(['current','ablated','ablated','current']*2):
                result=run(a.current if label=='current' else a.ablated,a.output/f'{i:02d}-{label}',values)
                result['label']=label;results.append(result)
                (a.output/'summary.json').write_text(json.dumps(results,indent=2)+'\n')
                print(json.dumps({'run':i,'label':label,'successes':result['successes'],'corruptions':result['corruptions']}),flush=True)
            assert all(r['successes']==9 and r['corruptions']==3 for r in results if r['label']=='current')
            assert all(r['successes']==0 and r['corruptions']==12 for r in results if r['label']=='ablated')
        finally:
            node.send_signal(signal.SIGINT)
            try:node.wait(15)
            except subprocess.TimeoutExpired:node.kill();node.wait()

if __name__=='__main__':main()
