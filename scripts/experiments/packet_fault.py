#!/usr/bin/env python3
"""A real proxy session under a private-namespace packet impairment.

Internal half of packet_faults.sh, executed inside the client namespace.
Timeouts are censored observations, never claimed as network-failure detection.
"""
import argparse
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import threading
import time


def exact(sock, count):
    data = bytearray()
    while len(data) < count:
        block = sock.recv(count-len(data))
        if not block: raise EOFError('proxy closed')
        data.extend(block)
    return bytes(data)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--implementation', choices=['rust-current','xray'], required=True)
    p.add_argument('--fixture', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--case', choices=['idle-blackhole','idle-transient','write-blackhole','write-transient'], required=True)
    p.add_argument('--limit', type=float, default=100)
    a = p.parse_args(); a.output.mkdir(parents=True,exist_ok=True)
    values = dict(line.split('=',1) for line in (a.fixture/'handoff.env').read_text().splitlines())
    with socket.socket() as reserved:
        reserved.bind(('127.0.0.1',0)); port=reserved.getsockname()[1]
    node='10.144.10.2'
    if a.implementation=='xray':
        config=a.output/'client.json'
        config.write_text(json.dumps({'log':{'loglevel':'warning'},'inbounds':[{'listen':'127.0.0.1','port':port,'protocol':'socks','settings':{'auth':'noauth','udp':False}}],
        'outbounds':[{'protocol':'vless','settings':{'vnext':[{'address':node,'port':14443,'users':[{'id':values['RRC_INTEROP_USER_ID'],'encryption':'none','flow':'xtls-rprx-vision'}]}]},
        'streamSettings':{'network':'tcp','security':'reality','realitySettings':{'serverName':'localhost','fingerprint':'chrome','publicKey':values['RRC_INTEROP_PUBLIC_KEY'],'shortId':values['RRC_INTEROP_SHORT_ID']}}}]}))
        if os.environ.get('XRAY_MATCHED_TIMERS') == '1':
            data=json.loads(config.read_text())
            timers={'tcpKeepAliveIdle':30,'tcpKeepAliveInterval':10,'tcpUserTimeout':60000}
            data['outbounds'][0]['streamSettings']['sockopt']=timers
            data['inbounds'][0]['streamSettings']={'sockopt':timers}
            config.write_text(json.dumps(data))
        command=[str(a.binary),'run','-config',str(config)]
    else:
        config=a.output/'client.toml'
        config.write_text(f'''[listen]\nsocks5="127.0.0.1:{port}"\nhttp=""\n[[node]]\nname="isolated-node"\naddress="{node}"\nport=14443\nuserId="{values['RRC_INTEROP_USER_ID']}"\n[node.reality]\npublicKey="{values['RRC_INTEROP_PUBLIC_KEY']}"\nshortId="{values['RRC_INTEROP_SHORT_ID']}"\nserverName="localhost"\n''')
        command=[str(a.binary),'run','--config',str(config),'--log-level','debug']
    result={'xray_matched_timers':os.environ.get('XRAY_MATCHED_TIMERS')=='1','case':a.case,'implementation':a.implementation,'censored':False,'detected':False,'recovered':False,'restore_seconds':float(os.environ.get('RESTORE_SECONDS','5')) if a.case.endswith('transient') else None}
    with (a.output/'client.log').open('w') as log:
        process=subprocess.Popen(command,stdout=log,stderr=subprocess.STDOUT)
        try:
            for _ in range(100):
                try: app=socket.create_connection(('127.0.0.1',port),.2);break
                except OSError:
                    if process.poll() is not None: raise RuntimeError('client startup failed')
                    time.sleep(.05)
            else: raise TimeoutError('listener startup')
            with app:
                app.settimeout(15)
                app.sendall(b'\x05\x01\x00');assert exact(app,2)==b'\x05\x00'
                app.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01'+struct.pack('!H',14444))
                head=exact(app,4);assert head[:2]==b'\x05\x00'
                exact(app,(4 if head[3]==1 else 16)+2)
                app.sendall(b'initial-echo');assert exact(app,12)==b'initial-echo'
                (a.output/'READY').write_text('ready')
                until=time.monotonic()+15
                while not (a.output/'DROPPED').exists():
                    if time.monotonic()>until: raise TimeoutError('controller did not arm impairment')
                    time.sleep(.01)
                started=time.monotonic();app.setblocking(True);app.settimeout(None)
                writer_result=[]
                payload=bytes(range(256))*32768
                if a.case.startswith('write'):
                    def write():
                        try: app.sendall(payload);writer_result.append('accepted')
                        except OSError as error:writer_result.append(type(error).__name__)
                    threading.Thread(target=write,daemon=True).start()
                received=bytearray()
                probe_sent=False
                while time.monotonic()-started<a.limit:
                    if (a.output/'RESTORED').exists() and not probe_sent and a.case.startswith('idle'):
                        app.sendall(b'recovered-echo');probe_sent=True
                    readable,_,_=select.select([app],[],[],.1)
                    if readable:
                        try: block=app.recv(65536)
                        except OSError as error:
                            result.update(detected=True,terminal=type(error).__name__);break
                        if not block:
                            result.update(detected=True,terminal='EOF');break
                        received.extend(block)
                        if probe_sent and received==b'recovered-echo':result['recovered']=True;break
                        if a.case.startswith('write') and len(received)==len(payload):
                            assert received==payload,'corruption/reordering/duplication'
                            result['recovered']=True;break
                        assert len(received)<=len(payload),'duplicated payload'
                else:result['censored']=True
                result['elapsed_seconds']=time.monotonic()-started
                result['bytes_received']=len(received)
                result['writer_observation']=list(writer_result) # snapshot before deliberate cleanup closes the app
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGINT)
                try:process.wait(15)
                except subprocess.TimeoutExpired:process.kill();process.wait()
            (a.output/'result.json').write_text(json.dumps(result,indent=2)+'\n')
            # Local ephemeral secrets are never part of collected evidence.
            config.unlink(missing_ok=True)
    print(json.dumps(result),flush=True)

if __name__=='__main__':main()
