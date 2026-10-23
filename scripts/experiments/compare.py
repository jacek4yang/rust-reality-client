#!/usr/bin/env python3
"""Interleaved baseline/current/Xray experiments against pinned rust-reality.

Supply already-built executables. Runs sequentially, without concurrent build
work. An external steady background soak, if any, must be named in --context.
No aggregate superiority claim is made: retain all per-run results and failures.
"""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--current', type=Path, required=True)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--xray', type=Path, required=True)
    parser.add_argument('--seconds', type=int, default=120)
    parser.add_argument('--rounds', type=int, default=2)
    parser.add_argument('--context', required=True)
    parser.add_argument('--output', type=Path, default=ROOT/'target/comparison')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    binaries = {'rust-current': args.current, 'rust-baseline': args.baseline, 'xray': args.xray}
    report = {'context': args.context, 'platform': platform.platform(), 'seconds_per_run': args.seconds,
              'rounds': args.rounds, 'ordering': ['rust-baseline','rust-current','xray','xray','rust-current','rust-baseline'],
              'binaries': {name: hashlib.sha256(path.read_bytes()).hexdigest() for name,path in binaries.items()},
              'runs': [], 'limitations': ['loopback, not WAN performance', 'no bandwidth or RTT impairment', 'default client policies differ; configurations are documented by the harness', 'no billing or provider-API measurements']}
    try:
        for round_ in range(args.rounds):
            for label in report['ordering']:
                number = len(report['runs']) + 1
                out = args.output / f'{number:02d}-{label}'
                log = args.output / f'{number:02d}-{label}.log'
                command = [sys.executable, str(ROOT/'scripts/interop/application_soak.py'), '--seconds', str(args.seconds), '--implementation', label,
                           '--binary', str(binaries[label].resolve()), '--output', str(out.resolve()), '--quiet-client', '--quiet-seconds', '3']
                started = time.time()
                with log.open('w') as output:
                    run = subprocess.run(command, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT)
                data = json.loads((out/'report.json').read_text()) if (out/'report.json').exists() else {'passed':False, 'error':'no report'}
                record = {'round':round_+1, 'label':label, 'exit_code':run.returncode, 'started_unix':started, 'result':data}
                report['runs'].append(record)
                (args.output/'comparison.json').write_text(json.dumps(report,indent=2)+'\n')
                print(json.dumps({'run':number,'label':label,'passed':data['passed'],'p99_ms':data.get('roundtrip_p99_ms')}),flush=True)
    finally:
        (args.output/'comparison.json').write_text(json.dumps(report,indent=2)+'\n')
    if any(not run['result']['passed'] for run in report['runs']): raise SystemExit(1)

if __name__ == '__main__': main()
