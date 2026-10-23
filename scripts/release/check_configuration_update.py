"""Narrow v0.1.1 configuration-update gate; never re-label old endurance runs."""
import hashlib
import json
from pathlib import Path
import subprocess
import tomllib

BASE_COMMIT = '3cb7c5d3247180b8e9e09958028f950041f3b864'
ALLOWED_RUNTIME = {'Cargo.toml', 'Cargo.lock', 'src/main.rs', 'src/config.rs',
                   'src/config/json.rs', 'src/config/json_tests.rs'}
JSON_PACKAGES = {'serde_json', 'itoa', 'memchr', 'zmij'}


def verify_delta(baseline, actual, old_cargo, new_cargo, old_lock, new_lock):
    changed = {p for p in baseline.keys() | actual.keys() if baseline.get(p) != actual.get(p)}
    assert changed <= ALLOWED_RUNTIME, 'non-configuration runtime changed; new endurance qualification required'
    assert baseline.keys() <= actual.keys(), 'baseline runtime file removed'
    expected_cargo = json.loads(json.dumps(old_cargo))
    expected_cargo['package']['version'] = '0.1.1'
    expected_cargo['dependencies']['serde_json'] = '1'
    assert new_cargo == expected_cargo, 'unexpected manifest/dependency/profile change'
    assert old_lock['version'] == new_lock['version']
    def identity(p): return (p['name'], p['version'], p.get('source'))
    old = {identity(p): p for p in old_lock['package']}
    new = {identity(p): p for p in new_lock['package']}
    assert len(old) == len(old_lock['package']) and len(new) == len(new_lock['package']), 'duplicate package identities need explicit review'
    old_names = {key[0] for key in old}
    new_names = {key[0] for key in new}
    assert new_names - old_names == JSON_PACKAGES, 'unexpected new dependency'
    assert old_names <= new_names, 'dependency removed'
    expected_existing = set()
    for key, package in old.items():
        expected = json.loads(json.dumps(package))
        if key[0] == 'rust-reality-client':
            expected['version'] = '0.1.1'
            expected['dependencies'] = sorted(expected['dependencies'] + ['serde_json'])
        expected_key = identity(expected)
        expected_existing.add(expected_key)
        assert new.get(expected_key) == expected, 'existing dependency changed; requires separate review'
    assert {key for key in new if key[0] not in JSON_PACKAGES} == expected_existing, 'unexpected extra existing dependency version'


def validate(root: Path, actual, baseline):
    meta = json.loads((root/'docs/experiments/release-config-update.json').read_text())
    assert meta['version'] == '0.1.1' and meta['mode'] == 'configuration-update'
    assert meta['baseline_commit'] == BASE_COMMIT
    assert meta['fresh_five_hour_endurance'] is False
    assert actual == meta['files'], 'source changed after configuration-update review'
    def old_file(name):
        return subprocess.check_output(['git','show',f'{BASE_COMMIT}:{name}'],cwd=root)
    # A shallow/missing baseline is a failure, never permission to skip comparison.
    old_cargo_bytes, old_lock_bytes = old_file('Cargo.toml'), old_file('Cargo.lock')
    assert hashlib.sha256(old_cargo_bytes).hexdigest() == baseline['Cargo.toml']
    assert hashlib.sha256(old_lock_bytes).hexdigest() == baseline['Cargo.lock']
    verify_delta(baseline, actual,
                 tomllib.loads(old_cargo_bytes.decode()),tomllib.loads((root/'Cargo.toml').read_text()),
                 tomllib.loads(old_lock_bytes.decode()),tomllib.loads((root/'Cargo.lock').read_text()))
    print('PASS: exact v0.1.1 configuration-update scope; fresh CI/package regressions required; NO new five-hour claim')
