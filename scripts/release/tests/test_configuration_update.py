"""Synthetic fail-closed scope tests, not transport or endurance evidence."""
import copy
import importlib.util
from pathlib import Path
import unittest
spec = importlib.util.spec_from_file_location('config_gate', Path(__file__).resolve().parents[1]/'check_configuration_update.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

class ConfigurationUpdate(unittest.TestCase):
    def setUp(self):
        self.base={'src/transport.rs':'same','Cargo.toml':'old','Cargo.lock':'old','src/config.rs':'old'}
        self.actual=dict(self.base, **{'Cargo.toml':'new','Cargo.lock':'new','src/config.rs':'new','src/config/json.rs':'added'})
        self.old_cargo={'package':{'version':'0.1.0'},'dependencies':{'tokio':'1'}}
        self.new_cargo={'package':{'version':'0.1.1'},'dependencies':{'tokio':'1','serde_json':'1'}}
        self.old_lock={'version':4,'package':[{'name':'rust-reality-client','version':'0.1.0','dependencies':['tokio']},{'name':'tokio','version':'1','checksum':'original'}]}
        self.new_lock=copy.deepcopy(self.old_lock)
        self.new_lock['package'][0].update(version='0.1.1',dependencies=['serde_json','tokio'])
        self.new_lock['package'] += [{'name':n,'version':'1'} for n in sorted(gate.JSON_PACKAGES)]
    def verify(self):
        gate.verify_delta(self.base,self.actual,self.old_cargo,self.new_cargo,self.old_lock,self.new_lock)
    def test_only_configuration_delta_passes(self): self.verify()
    def test_transport_change_is_rejected(self):
        self.actual['src/transport.rs']='changed'
        with self.assertRaises(AssertionError):self.verify()
    def test_new_unreviewed_runtime_is_rejected(self):
        self.actual['src/backdoor.rs']='new'
        with self.assertRaises(AssertionError):self.verify()
    def test_removed_configuration_file_is_rejected(self):
        del self.actual['src/config.rs']
        with self.assertRaises(AssertionError):self.verify()
    def test_dependency_upgrade_is_rejected(self):
        self.new_lock['package'][1]['version']='2'
        with self.assertRaises(AssertionError):self.verify()
    def test_checksum_mutation_is_rejected(self):
        self.new_lock['package'][1]['checksum']='changed'
        with self.assertRaises(AssertionError):self.verify()
    def test_extra_dependency_is_rejected(self):
        self.new_lock['package'].append({'name':'extra','version':'1'})
        with self.assertRaises(AssertionError):self.verify()
    def test_manifest_feature_change_is_rejected(self):
        self.new_cargo['dependencies']['tokio']={'version':'1','features':['full']}
        with self.assertRaises(AssertionError):self.verify()
    def test_wrong_version_is_rejected(self):
        self.new_cargo['package']['version']='0.1.2'
        with self.assertRaises(AssertionError):self.verify()
    def test_duplicate_package_name_is_rejected(self):
        self.new_lock['package'].append(copy.deepcopy(self.new_lock['package'][1]))
        with self.assertRaises(AssertionError):self.verify()
