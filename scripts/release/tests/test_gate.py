"""Synthetic unit tests of release rejection logic, not endurance evidence."""
import copy
import gzip
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

GATE = Path(__file__).resolve().parents[1] / 'check_evidence.py'


class ReleaseGate(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root/'scripts/release').mkdir(parents=True)
        (self.root/'docs/experiments').mkdir(parents=True)
        (self.root/'src').mkdir()
        shutil.copyfile(GATE, self.root/'scripts/release/check_evidence.py')
        (self.root/'src/lib.rs').write_text('// synthetic fixture\n')
        subprocess.run(['git','init','-q',str(self.root)],check=True)
        subprocess.run(['git','-C',str(self.root),'add','src/lib.rs'],check=True)
        (self.root/'docs/RELEASE_NOTES.md').write_text('Synthetic test notes\n')
        manifest = {'binary_sha256':'synthetic-not-a-real-binary',
                    'files':{'src/lib.rs':hashlib.sha256((self.root/'src/lib.rs').read_bytes()).hexdigest()}}
        (self.root/'docs/experiments/release-runtime.json').write_text(json.dumps(manifest))
        self.result = {'passed':True,'requested_seconds':86400,'wall_seconds':86400,
                       'binary_sha256':'synthetic-not-a-real-binary','handoff':True,
                       'with_recovery':True,'origin_only_control':False,
                       'upstream_commit':'e3fc3dc36b931baec042074d6c88e928caf6941f',
                       'node_termination':{'terminal_visible':True},
                       'resources':[{'active':0,'panicked':0,'connectionsAvailable':256,
                                     'handshakesAvailable':32,'sparesAvailable':16,'probesAvailable':4}],
                       'workloads':{'churn':150000,'recovery':{'origin_resets':2500,
                           'local_cancellations':2500,'explicit_reconnections':5000}}}
        for kind in ('http','socks'):
            for tls in ('tls12','tls13'):
                self.result['workloads'][f'wss-{kind}-{tls}']={'close_code':1000,'wall_seconds':86400}
                self.result['workloads'][f'sse-{kind}-{tls}']={'events':400000}

    def run_gate(self, result=None, write=True):
        if write:
            with gzip.open(self.root/'docs/experiments/release-24h.json.gz','wt') as f:
                json.dump(self.result if result is None else result,f)
        return subprocess.run(['python3',str(self.root/'scripts/release/check_evidence.py')],
                              capture_output=True,timeout=5).returncode

    def test_complete_synthetic_record_is_accepted(self):
        self.assertEqual(self.run_gate(),0)

    def test_missing_record_is_rejected(self):
        self.assertNotEqual(self.run_gate(write=False),0)

    def test_draft_notes_are_rejected(self):
        (self.root/'docs/RELEASE_NOTES.md').write_text('PENDING_ENDURANCE')
        self.assertNotEqual(self.run_gate(),0)

    def test_changed_runtime_is_rejected(self):
        (self.root/'src/lib.rs').write_text('// changed\n')
        self.assertNotEqual(self.run_gate(),0)

    def test_added_runtime_file_is_rejected(self):
        (self.root/'src/new.rs').write_text('// new\n')
        subprocess.run(['git','-C',str(self.root),'add','src/new.rs'],check=True)
        self.assertNotEqual(self.run_gate(),0)

    def test_incomplete_or_wrong_records_are_rejected(self):
        changes = [('passed',False),('requested_seconds',3600),('wall_seconds',86399),
                   ('binary_sha256','wrong'),('handoff',False),('with_recovery',False),
                   ('origin_only_control',True),('upstream_commit','wrong')]
        for field,value in changes:
            with self.subTest(field=field):
                result=copy.deepcopy(self.result);result[field]=value
                self.assertNotEqual(self.run_gate(result),0)

    def test_resource_leak_or_short_application_stream_is_rejected(self):
        for key in ('active','panicked','connectionsAvailable','handshakesAvailable','sparesAvailable','probesAvailable'):
            with self.subTest(resource=key):
                result=copy.deepcopy(self.result);result['resources'][0][key]+=1
                self.assertNotEqual(self.run_gate(result),0)
        result=copy.deepcopy(self.result)
        result['workloads']['wss-http-tls13']['wall_seconds']=3600
        self.assertNotEqual(self.run_gate(result),0)


if __name__=='__main__':unittest.main()
