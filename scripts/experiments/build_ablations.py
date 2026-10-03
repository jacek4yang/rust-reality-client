#!/usr/bin/env python3
"""Build isolated experimental variants. Never modify the working checkout.

Usage: python scripts/experiments/build_ablations.py --revision HEAD
Requires Rust 1.98.1. Outputs immutable source/binary hashes and exact patches.
These variants are experimental controls, not supported production binaries.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--only', choices=['no-session-cost','no-client-keepalive','no-hedge','with-user-timeout'])
    parser.add_argument('--revision', default='HEAD')
    parser.add_argument('--output', type=Path, default=ROOT / 'target/ablations')
    args = parser.parse_args()
    revision = subprocess.check_output(['git', 'rev-parse', args.revision], cwd=ROOT, text=True).strip()
    args.output.mkdir(parents=True, exist_ok=True)
    variants = {
        'no-session-cost': ('src/scheduler.rs', '.saturating_add(self.shared.quality[index].penalty_ms(now_ms))', '.saturating_add(0)'),
        'no-client-keepalive': ('src/transport/socket.rs', '        KEEPALIVE_COUNT,\n    ))', '        KEEPALIVE_COUNT,\n    ))?;\n    socket.set_keepalive(false)'),
        'no-hedge': ('src/scheduler.rs', 'max_spares: MAX_HEDGED_ATTEMPTS,', 'max_spares: 0,'),
        'with-user-timeout': ('src/transport/socket.rs', '        KEEPALIVE_COUNT,\n    ))', '        KEEPALIVE_COUNT,\n    ))?;\n    socket.set_tcp_user_timeout(Some(Duration::from_secs(60)))?;\n    if socket.tcp_user_timeout()? != Some(Duration::from_secs(60)) { return Err(io::Error::other("user timeout read-back mismatch")); }\n    Ok(())'),
    }
    records = []
    for name, (file, old, new) in variants.items():
        if args.only and name != args.only: continue
        directory = args.output / name
        if directory.exists():
            raise SystemExit(f'refusing to overwrite prior experiment: {directory}')
        subprocess.run(['git', 'worktree', 'add', '--detach', str(directory), revision], cwd=ROOT, check=True)
        target = directory / file
        source = target.read_text()
        assert source.count(old) == 1, f'{name}: source anchor changed, inspect before adapting'
        target.write_text(source.replace(old, new))
        patch = subprocess.check_output(['git', 'diff', '--', file], cwd=directory)
        (args.output / f'{name}.patch').write_bytes(patch)
        # Separate target directories prevent Cargo from reusing a different
        # worktree's executable under an identical package name.
        with (args.output / f'{name}.build.log').open('w') as log:
            subprocess.run(['cargo', '+1.98.1', 'build', '--release', '--locked'], cwd=directory, stdout=log, stderr=subprocess.STDOUT, check=True)
        binary = directory / 'target/release/rust-reality-client'
        records.append({'name': name, 'base_revision': revision, 'patch_sha256': hashlib.sha256(patch).hexdigest(),
                        'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'binary': str(binary.resolve())})
        (args.output / 'manifest.json').write_text(json.dumps(records, indent=2)+'\n')
        print(json.dumps(records[-1]), flush=True)

if __name__ == '__main__': main()
