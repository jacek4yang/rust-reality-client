#!/usr/bin/env python3
"""Fresh-client ABBA trials: bounded delayed hedge versus the no-hedge control.

One actual pinned server, a deliberately slow entry path and an intact spare.
Path delay is a userspace delay (not packet-level RTT/loss). Compare setup
latency; never infer steady-state throughput or established-session migration.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts/experiments'))
from session_feedback import Bridge
sys.path.insert(0,str(ROOT/'scripts/interop'))
from application_soak import tunnel,free_port,recv_exact


def trial(binary,out,values,delay):
    out.mkdir(parents=True,exist_ok=True)
    lead,spare=Bridge(delay),Bridge()
    port=free_port()
    text=f'[listen]\nsocks5="127.0.0.1:{port}"\nhttp=""\n'
    for name,bridge in [('lead',lead),('spare',spare)]:
        text+=f'''[[node]]\nname="{name}"\naddress="127.0.0.1"\nport={bridge.port}\nuserId="{values['RRC_INTEROP_USER_ID']}"\n[node.reality]\npublicKey="{values['RRC_INTEROP_PUBLIC_KEY']}"\nshortId="{values['RRC_INTEROP_SHORT_ID']}"\nserverName="localhost"\n'''
    config=out/'client.toml';config.write_text(text)
    with (out/'client.log').open('w') as log:
        process=subprocess.Popen([str(binary.resolve()),'run','--config',str(config),'--log-level','debug'],stdout=log,stderr=subprocess.STDOUT)
        try:
            for _ in range(100):
                try:
                    with socket.create_connection(('127.0.0.1',port),.1):break
                except OSError:time.sleep(.05)
            start=time.monotonic()
            with tunnel(port,14444,'socks') as app:
                setup=time.monotonic()-start
                payload=b'one-application-payload'*1000
                app.sendall(payload);assert recv_exact(app,len(payload))==payload
            result={'setup_seconds':setup,'application_bytes':len(payload),'lead_attempts':len(lead.connections),'spare_attempts':len(spare.connections),'delay_per_bridge_read_seconds':delay}
            assert result['lead_attempts']==1 and result['spare_attempts']<=1
            return result
        finally:
            process.send_signal(signal.SIGINT)
            try:process.wait(15)
            except subprocess.TimeoutExpired:process.kill();process.wait()
            lead.close();spare.close();config.unlink(missing_ok=True)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--current',type=Path,required=True);p.add_argument('--ablated',type=Path,required=True)
    p.add_argument('--output',type=Path,default=ROOT/'target/hedge-ablation')
    a=p.parse_args();a.output=a.output.resolve();a.output.mkdir(parents=True,exist_ok=True)
    results={'binaries':{'current':hashlib.sha256(a.current.read_bytes()).hexdigest(),'ablated':hashlib.sha256(a.ablated.read_bytes()).hexdigest()},'trials':[]}
    env=dict(os.environ,INTEROP_OUTPUT_DIR=str(a.output/'fixture'))
    with (a.output/'node.log').open('w') as log:
        node=subprocess.Popen(['bash',str(ROOT/'scripts/interop/upstream-server.sh')],env=env,stdout=log,stderr=subprocess.STDOUT)
        try:
            for _ in range(120):
                if 'listener_started' in (a.output/'node.log').read_text():break
                if node.poll() is not None:raise RuntimeError('node startup')
                time.sleep(.5)
            values=dict(line.split('=',1) for line in (a.output/'fixture/handoff.env').read_text().splitlines())
            for delay in [0,.2]:
                for label in ['current','ablated','ablated','current']*2:
                    index=len(results['trials'])
                    result=trial(a.current if label=='current' else a.ablated,a.output/f'{index:02d}-{label}',values,delay)
                    result['label']=label;results['trials'].append(result)
                    (a.output/'summary.json').write_text(json.dumps(results,indent=2)+'\n')
                    print(json.dumps(result),flush=True)
            for r in results['trials']:
                if r['delay_per_bridge_read_seconds']==0 or r['label']=='ablated':assert r['spare_attempts']==0
                else:assert r['spare_attempts']==1
        finally:
            node.send_signal(signal.SIGINT)
            try:node.wait(15)
            except subprocess.TimeoutExpired:node.kill();node.wait()

if __name__=='__main__':main()
