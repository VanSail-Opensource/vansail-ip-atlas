import importlib.util
import copy
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.release_contract.contracts import ContractError, canonical_bytes

spec = importlib.util.spec_from_file_location('production_build', Path(__file__).with_name('production-build.py'))
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


class ProductionBuildTransitionTests(unittest.TestCase):
    def test_rebuild_republishes_only_typed_phase_diagnostics(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / '.atlas-private').mkdir()
            phase = {'phase': 'benchmark-measure', 'event': 'begin', 'elapsed_ms': 0, 'ok': True}
            def execute(argv, **kwargs):
                kwargs['stderr'].write(b'private parser data\n')
                kwargs['stderr'].write(b'ATLAS_COMPILE_PHASE ' + canonical_bytes(phase) + b'\n')
                kwargs['stderr'].write(b'ATLAS_COMPILE_PHASE {"phase":"private"}\n')
                return type('CompletedProcess', (), {'poll': lambda self: 1, 'returncode': 1})()
            diagnostics = io.StringIO()
            with patch.object(build.subprocess, 'Popen', side_effect=execute), contextlib.redirect_stderr(diagnostics):
                self.assertEqual(build.command(['/fixed/atlas', 'benchmark-state'], root), 1)
            self.assertEqual(diagnostics.getvalue(), 'ATLAS_COMPILE_PHASE ' + canonical_bytes(phase).decode('ascii') + '\n')

    def test_scratch_scan_counts_all_file_bytes_and_does_not_follow_links(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ('.atlas-private', 'build-private/nested', 'web/.output'):
                directory = root / name
                directory.mkdir(parents=True)
                (directory / 'payload').write_bytes(b'123')
            path = root / 'build-private/nested/payload'
            os.link(path, path.with_name('hardlink'))
            (root / 'outside').mkdir()
            (root / 'outside/excluded').write_bytes(b'12345')
            (root / 'build-private/outside').symlink_to(root / 'outside', target_is_directory=True)
            self.assertEqual(build.disk_bytes(root), 12)
            path.with_name('symlink').symlink_to(path)
            with self.assertRaises(ContractError):
                build.disk_bytes(root)

    def test_single_replay_preserves_warm_preparation_before_measured_timer(self):
        for scenario in ('cold_full', 'warm_unchanged'):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root/'.atlas-private').mkdir(); (root/'build-private').mkdir()
                (root/'.atlas-private/production-receipt.json').write_text(json.dumps({'evaluated_at':100,'normalized_state_sha256':'a'*64}))
                profile = root/'profile.json'; profile.write_bytes(canonical_bytes(build.ENVELOPE))
                events = []
                def tick():
                    events.append('timer')
                    return 1 if events.count('timer') == 1 else 1000002
                def command(argv, workspace, metrics=None, **kwargs):
                    self.assertEqual(workspace, root)
                    self.assertEqual(argv[1:4], ['benchmark-state','-workspace',str(root)])
                    self.assertEqual(argv[argv.index('-scenario')+1], scenario)
                    self.assertEqual(argv[argv.index('-clock')+1], '100')
                    if argv[-1] == '-prepare':
                        self.assertIsNone(metrics)
                        events.append('prepare')
                    else:
                        self.assertEqual(kwargs['atlas_commands'], {'benchmark-state':1})
                        self.assertEqual(kwargs['phase'], 'benchmark-state')
                        events.append('measure')
                        kwargs['stdout'].write(canonical_bytes({'schema_version':1,'scope':'authenticated-real-input-engineering-benchmark',
                            'scenario':scenario,'clock':100,'input_records':100,'normalized_input_bytes':1000,
                            'before_state_sha256':'a'*64,'after_state_sha256':'a'*64,'release_id':'b'*64,
                            'compile_exit_code':0,'transition':{}}))
                    return 0
                report = {'scenarios':[]}
                with patch.object(build, 'ROOT', root), patch.dict(build.os.environ, {'ATLAS_RUNNER_PROFILE':str(profile)}), \
                        patch.object(build, 'command', command), patch.object(build.time, 'monotonic_ns', tick):
                    build.measure_replay(Path('/fixed/atlas'), report, case=scenario, sample=2)
                self.assertEqual(events, (['prepare'] if scenario != 'cold_full' else []) + ['timer','measure','timer'])
                self.assertEqual(len(report['scenarios']), 1)
                self.assertEqual(report['scenarios'][0]['sample'], 2)
                self.assertEqual(report['scenarios'][0]['runtime_ms'], 2)  # Round up, never hide boundary overshoot.
                self.assertEqual(list((root/'build-private').iterdir()), [])
                self.assertEqual(list((root/'.atlas-private').glob('benchmark-metrics-*')), [])

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
