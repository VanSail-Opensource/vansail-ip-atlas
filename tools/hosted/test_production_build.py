import importlib.util
import copy
from pathlib import Path
import tempfile
import unittest

from tools.release_contract.contracts import ContractError, canonical_bytes

spec = importlib.util.spec_from_file_location('production_build', Path(__file__).with_name('production-build.py'))
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


class ProductionBuildTransitionTests(unittest.TestCase):
    def write(self, path, values):
        path.write_bytes(b''.join(canonical_bytes({'source_id':'fixture-source','semantic_sha256':value}) + b'\n' for value in values))

    def test_external_comparison_preserves_duplicate_records_and_actual_one_percent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);before,after=root/'before.ndjson',root/'after.ndjson'
            self.write(before,['a'*64]*100)
            self.write(after,['a'*64]*99+['b'*64])
            result=build.transition(before,after,root)
            self.assertEqual(result['before_records'],100)
            self.assertEqual(result['after_records'],100)
            self.assertEqual(result['changed_records'],1)
            self.assertEqual(result['added_records'],1)
            self.assertEqual(result['removed_records'],1)
            self.assertEqual(list(root.glob('fingerprint-sort-*')),[])

    def test_unchanged_and_withdrawal_are_computed_from_rows(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);before,after=root/'before.ndjson',root/'after.ndjson'
            self.write(before,['a'*64,'b'*64]);self.write(after,['b'*64,'a'*64])
            self.assertEqual(build.transition(before,after,root)['changed_records'],0)
            self.write(after,[])
            result=build.transition(before,after,root)
            self.assertEqual(result['removed_records'],2)
            self.assertEqual(result['after_records'],0)

    def test_bootstrap_cannot_point_outside_the_private_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);private=root/'private';private.mkdir();(root/'outside').mkdir()
            with self.assertRaises(ContractError):
                build.private_path(private,'../outside')

    def test_actual_go_process_records_bind_commands_totals_and_failures(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory=Path(temporary);token='a'*32
            record={'allocated_bytes':12345,'allocation_count':123,'command':'compile-production','exit_code':1,
                'invocation':token,'pid':321,'schema_version':1,'scope':build.GO_PROCESS_SCOPE}
            path=directory/(token+'-321-'+'b'*16+'.json');path.write_bytes(canonical_bytes(record))
            records=build.collect_go_allocations(directory,token,'compile-production',{'compile-production':1},321,1)
            self.assertEqual(sum(item['allocation_count'] for item in records),123)
            self.assertEqual(sum(item['allocated_bytes'] for item in records),12345)
            for key,value in [('allocation_count',None),('allocated_bytes',True),('invocation','c'*32),('exit_code',0),('pid',322),('command','intake')]:
                invalid=copy.deepcopy(record);invalid[key]=value;path.write_bytes(canonical_bytes(invalid))
                with self.subTest(key=key),self.assertRaises(ContractError):
                    build.collect_go_allocations(directory,token,'compile-production',{'compile-production':1},321,1)
            path.unlink()
            with self.assertRaises(ContractError):
                build.collect_go_allocations(directory,token,'compile-production',{'compile-production':1},321,1)

    def test_packaging_requires_every_actual_go_verifier_and_inspector(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory=Path(temporary);token='a'*32
            expected={'inspect':1,'verify-production':2}
            for pid,command in enumerate(('inspect','verify-production','verify-production'),100):
                record={'allocated_bytes':12345,'allocation_count':123,'command':command,'exit_code':0,
                    'invocation':token,'pid':pid,'schema_version':1,'scope':build.GO_PROCESS_SCOPE}
                (directory/(token+'-'+str(pid)+'-'+'b'*16+'.json')).write_bytes(canonical_bytes(record))
            self.assertEqual(len(build.collect_go_allocations(directory,token,'prepare-static',expected,999,0)),3)
            next(directory.iterdir()).unlink()
            with self.assertRaises(ContractError):
                build.collect_go_allocations(directory,token,'prepare-static',expected,999,0)


if __name__=='__main__':
    unittest.main()
