#!/usr/bin/env python3
"""Fail closed unless committed continuous endurance evidence matches runtime."""
import gzip
import hashlib
import json
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parents[2]
assert 'PENDING_ENDURANCE' not in (root / 'docs/RELEASE_NOTES.md').read_text(), 'release notes are still a draft'
manifest = json.loads((root / 'docs/experiments/release-runtime.json').read_text())
files = subprocess.check_output(['git', 'ls-files', '-z', 'src', 'Cargo.toml', 'Cargo.lock'], cwd=root).decode().split('\0')
actual = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in files if name}
assert actual == manifest['files'], 'runtime changed after the recorded endurance run'
with gzip.open(root / 'docs/experiments/release-24h.json.gz', 'rt') as stream:
    result = json.load(stream)
assert result['passed'] is True
assert result['requested_seconds'] >= 86400 and result['wall_seconds'] >= 86400
assert result['binary_sha256'] == manifest['binary_sha256']
assert result['handoff'] and result['with_recovery'] and not result['origin_only_control']
assert result['upstream_commit'] == 'e3fc3dc36b931baec042074d6c88e928caf6941f'
assert result['node_termination']['terminal_visible']
work = result['workloads']
assert work['churn'] > 100000
assert work['recovery']['origin_resets'] >= 2000
assert work['recovery']['local_cancellations'] >= 2000
assert work['recovery']['explicit_reconnections'] >= 4000
for kind in ('http', 'socks'):
    for tls in ('tls12', 'tls13'):
        assert work[f'wss-{kind}-{tls}']['close_code'] == 1000
        assert work[f'wss-{kind}-{tls}']['wall_seconds'] >= 86390
        assert work[f'sse-{kind}-{tls}']['events'] > 300000
final = result['resources'][-1]
assert final['active'] == 0 and final['panicked'] == 0
for key, value in [('connectionsAvailable', 256), ('handshakesAvailable', 32), ('sparesAvailable', 16), ('probesAvailable', 4)]:
    assert final[key] == value
print('PASS: continuous 24-hour evidence, application integrity and unchanged runtime')
