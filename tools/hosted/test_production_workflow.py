import json
import contextlib
import io
import os
from pathlib import Path
import tempfile
import sys
import unittest
from unittest.mock import patch

from tools.hosted import production_workflow as workflow
from tools.release_contract.contracts import ContractError


class CandidateClockTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.private = self.root / '.atlas-private'
        self.private.mkdir()
        (self.root / 'build-private').mkdir()
        self.state = self.private / 'state-v1.json'
        self.evaluated_at = 1794700800
        self.state.write_text(json.dumps({'Version': 2, 'EvaluatedAt': '2026-11-15T00:00:00Z'}))
        (self.private / 'workflow-context.json').write_text(json.dumps({'format_version':2,'head_sha':'a'*40,
            'integration_run_id':10,'integration_run_attempt':1,'intake_run_id':11,'intake_run_attempt':1}))
        self.environment = {'ATLAS_UPSTREAM_RUN':'11','ATLAS_UPSTREAM_ATTEMPT':'1','GITHUB_RUN_ID':'12',
                            'GITHUB_RUN_ATTEMPT':'1','GITHUB_SHA':'a'*40}

    def test_delayed_candidate_uses_intake_clock_only_for_compilation(self):
        with patch.object(workflow, 'ROOT', self.root), patch.dict(os.environ, self.environment), \
                patch.object(workflow.time, 'time', return_value=self.evaluated_at + 600), \
                patch.object(workflow, 'run') as run:
            workflow.candidate()

        commands = [call.args[0] for call in run.call_args_list]
        compile_command, verify_command, corpus_command = commands[:3]
        self.assertEqual(compile_command[1], 'compile-production')
        self.assertEqual(compile_command[compile_command.index('-clock') + 1], self.evaluated_at)
        self.assertEqual(verify_command, ['build-private/atlas', 'verify-production', '-workspace', self.root,
            '-atlas', self.root / 'build-private/production-atlas', '-receipt', self.private / 'production-receipt.json'])
        self.assertEqual(corpus_command[1], 'corpus')
        for command in commands[1:]:
            self.assertNotIn('-clock', command, 'Post-compile validation must use its fresh wall clock')
            self.assertNotIn('--now', command)
        self.assertTrue(any('tools/release_contract/prepare_static.py' in command for command in commands))
        self.assertTrue(any('native-gate' in command for command in commands))
        self.assertFalse(any('tools/hosted/production-build.py' in command for command in commands))
        self.assertEqual(commands[-1], ['python', 'tools/hosted/candidate.py', '--public', 'web/.output/public'])
        self.assertEqual(json.loads((self.private / 'workflow-context.json').read_text()), {
            'format_version':2,'integration_run_id':10,'integration_run_attempt':1,
            'intake_run_id':11,'intake_run_attempt':1,'candidate_run_id':12,'candidate_run_attempt':1,'head_sha':'a'*40})

    def test_invalid_or_future_intake_clock_stops_before_compilation(self):
        valid = {'Version': 2, 'EvaluatedAt': '2026-11-15T00:00:00Z'}
        documents = [[], {}, {**valid, 'Version': 1}, {**valid, 'Version': 2.0}, {**valid, 'Version': True}]
        for stamp in (None, 1794700800, '2026-11-15', '2026-11-15T00:00:00',
                      '2026-11-15T00:00:00+00:00', '2026-11-15T00:00:00.5Z',
                      '2026-02-30T00:00:00Z', '1969-12-31T23:59:59Z', '2026-11-15T00:10:01Z'):
            documents.append({**valid, 'EvaluatedAt': stamp})
        for document in documents:
            with self.subTest(document=document):
                self.state.write_text(json.dumps(document))
                with patch.object(workflow, 'ROOT', self.root), patch.dict(os.environ, self.environment), \
                        patch.object(workflow.time, 'time', return_value=self.evaluated_at + 600), \
                        patch.object(workflow, 'run') as run, self.assertRaises(ContractError):
                    workflow.candidate()
                run.assert_not_called()

    def test_missing_or_malformed_state_has_no_wall_clock_fallback(self):
        for payload in (None, b'{', b'\xff'):
            with self.subTest(payload=payload):
                if payload is None:
                    self.state.unlink()
                else:
                    self.state.write_bytes(payload)
                with patch.object(workflow, 'ROOT', self.root), patch.dict(os.environ, self.environment), \
                        patch.object(workflow, 'run') as run, self.assertRaises((ContractError, OSError)):
                    workflow.candidate()
                run.assert_not_called()

    def test_current_time_verification_failure_prevents_corpus_and_packaging(self):
        def run_command(command, **_):
            if command[1] == 'verify-production':
                raise ContractError('source expired during compilation')

        with patch.object(workflow, 'ROOT', self.root), patch.dict(os.environ, self.environment), \
                patch.object(workflow.time, 'time', return_value=self.evaluated_at + 600), \
                patch.object(workflow, 'run', side_effect=run_command) as run, self.assertRaises(ContractError):
            workflow.candidate()
        self.assertEqual([call.args[0][1] for call in run.call_args_list], ['compile-production', 'verify-production'])
        self.assertFalse((self.root / 'build-private/software-license-metadata.json').exists())

    def test_failed_child_logs_only_a_fixed_phase_and_keeps_details_private(self):
        public_out, public_err = io.StringIO(), io.StringIO()
        marker = 'synthetic-private-source-detail'
        with patch.object(workflow, 'ROOT', self.root), contextlib.redirect_stdout(public_out), \
                contextlib.redirect_stderr(public_err), self.assertRaises(ContractError):
            workflow.run([sys.executable, '-c', f'import sys; print({marker!r}); sys.exit(1)'])
        self.assertIn('Production step failed: stage-command', public_err.getvalue())
        self.assertNotIn(marker, public_out.getvalue() + public_err.getvalue())
        self.assertIn(marker, (self.private / 'stage.log').read_text())

    def test_failure_category_is_bounded_fixed_and_cannot_reuse_previous_command(self):
        log = self.private / 'stage.log'
        previous = b'context deadline exceeded\n'
        log.write_bytes(previous + b'private-source-identity and arbitrary error\n')
        self.assertEqual(workflow.failure_category(log, len(previous)), 'command-failed')
        log.write_bytes(previous + b'production_blocked: unqualified source capabilities: private-value\n')
        self.assertEqual(workflow.failure_category(log, len(previous)), 'source-capability')
        log.write_bytes(previous + b'x' * 70000 + b'\npipeline scratch ceiling exceeded\n')
        self.assertEqual(workflow.failure_category(log, len(previous)), 'scratch-budget')

    def test_intake_waits_for_longer_exact_head_integration_without_relaxing_identity(self):
        head = 'a' * 40
        event = self.root / 'event.json'
        event.write_text('{}')
        output, environment = self.root / 'github-output', self.root / 'github-env'
        env = {'GITHUB_REPOSITORY': workflow.REPOSITORY, 'GITHUB_REF': 'refs/heads/main',
               'GITHUB_SHA': head, 'GITHUB_EVENT_NAME': 'push', 'GITHUB_EVENT_PATH': str(event),
               'GITHUB_OUTPUT': str(output), 'GITHUB_ENV': str(environment)}
        polls = 0
        def api(route):
            nonlocal polls
            if route == 'branches/main':
                return {'commit': {'sha': head}}
            if route.startswith('actions/workflows/'):
                polls += 1
                return {'workflow_runs': [{'head_sha': head, 'event': 'push', 'id': 11,
                    'status': 'in_progress' if polls == 1 else 'completed', 'conclusion': 'success'}]}
            self.assertEqual(route, 'actions/runs/11')
            return {'head_sha': head, 'head_branch': 'main', 'path': '.github/workflows/p0-contracts.yml',
                    'head_repository': {'full_name': workflow.REPOSITORY}, 'status': 'completed',
                    'conclusion': 'success', 'event': 'push', 'run_attempt':1}
        with patch.dict(os.environ, env), patch.object(workflow, 'api', side_effect=api), \
                patch.object(workflow.time, 'monotonic', side_effect=[0, 3600]), \
                patch.object(workflow.time, 'sleep'):
            workflow.context('intake', None)
        self.assertEqual(output.read_text(), 'upstream_run_id=11\nupstream_run_attempt=1\n')
        self.assertEqual(polls, 2)
        with patch.dict(os.environ, env), patch.object(workflow, 'api', return_value={'commit': {'sha': 'b' * 40}}), \
                self.assertRaises(ContractError):
            workflow.context('intake', None)


class CompilePhaseDiagnosticsTests(unittest.TestCase):
    def test_aggregate_materializer_and_pipeline_phases_remain_nested_and_bounded(self):
        phases = ('materialize-seed', 'materialize-paths', 'materialize-asn-risk',
                  'materialize-spatial', 'materialize-asn', 'pipeline-sort',
                  'pipeline-merge', 'pipeline-classify', 'pipeline-partition', 'pipeline-publish')
        rows = [{'phase': 'build', 'event': 'begin', 'elapsed_ms': 0, 'ok': True}]
        for phase in phases:
            rows.extend(({'phase': phase, 'event': 'begin', 'elapsed_ms': 0, 'ok': True},
                         {'phase': phase, 'event': 'end', 'elapsed_ms': 123, 'ok': True}))
        rows.append({'phase': 'build', 'event': 'end', 'elapsed_ms': 1230, 'ok': True})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'stage.log'
            path.write_text(''.join('ATLAS_COMPILE_PHASE ' + json.dumps(row) + '\n' for row in rows))
            self.assertEqual(workflow.compile_phase_diagnostics(path, 0), rows)

    def test_compiler_log_output_exposes_only_allowlisted_phase_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            public_out, public_err = io.StringIO(), io.StringIO()
            rows = [{'phase': 'stage', 'event': 'begin', 'elapsed_ms': 0, 'ok': True},
                    {'phase': 'PRIVATE_SOURCE', 'event': 'begin', 'elapsed_ms': 0, 'ok': True},
                    {'phase': 'stage', 'event': 'end', 'elapsed_ms': 3, 'ok': False}]
            def execute(argv, **kwargs):
                kwargs['stderr'].write(b'private-token-marker\n')
                for row in rows:
                    kwargs['stderr'].write(('ATLAS_COMPILE_PHASE ' + json.dumps(row) + '\n').encode())
                return workflow.subprocess.CompletedProcess(argv, 1)
            with patch.object(workflow, 'ROOT', root), patch.object(workflow.subprocess, 'run', side_effect=execute), \
                 contextlib.redirect_stdout(public_out), contextlib.redirect_stderr(public_err), \
                 self.assertRaises(ContractError):
                workflow.run(['build-private/atlas', 'compile-production'])
            output = public_out.getvalue() + public_err.getvalue()
            self.assertIn('phase ended: stage elapsed_ms=3 ok=false', output)
            self.assertNotIn('private-token-marker', output)
            self.assertNotIn('PRIVATE_SOURCE', output)

    def test_fixed_schema_bounds_and_current_command_only(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'stage.log'
            begin = {'phase': 'stage', 'event': 'begin', 'elapsed_ms': 0, 'ok': True}
            end = {**begin, 'event': 'end', 'elapsed_ms': 123, 'ok': False}
            encode = lambda row: 'ATLAS_COMPILE_PHASE ' + json.dumps(row) + '\n'
            old = encode(begin) + encode(end)
            invalid = [{**begin, 'phase': 'PRIVATE_SOURCE'}, {**begin, 'elapsed_ms': True},
                       {**begin, 'elapsed_ms': -1}, {**begin, 'elapsed_ms': 86400001},
                       {**begin, 'ok': 'secret'}, {**begin, 'event': 'secret'},
                       {**begin, 'source': 'secret'}, {**begin, 'ok': False},
                       {**begin, 'elapsed_ms': 1}]
            path.write_text(old + 'secret token marker\n' + ''.join(map(encode, invalid)) + encode(begin) + encode(end))
            self.assertEqual(workflow.compile_phase_diagnostics(path, len(old)), [begin, end])
            path.write_text(encode(begin))
            self.assertEqual(workflow.compile_phase_diagnostics(path, 0), [begin])
            path.write_text(encode(begin) + encode({**end, 'phase': 'build'}))
            self.assertEqual(workflow.compile_phase_diagnostics(path, 0), [])
            path.write_text(encode(begin) * 65)
            self.assertEqual(workflow.compile_phase_diagnostics(path, 0), [])


if __name__ == '__main__':
    unittest.main()

class ParallelStageContextTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root/'.atlas-private').mkdir()
        (self.root/'build-private').mkdir()
        self.path = self.root/'.atlas-private/workflow-context.json'
        self.candidate = {'format_version':2,'head_sha':'a'*40,
            'integration_run_id':10,'integration_run_attempt':1,'intake_run_id':11,'intake_run_attempt':1,
            'candidate_run_id':12,'candidate_run_attempt':2}
        self.path.write_text(json.dumps(self.candidate))

    def environment(self, upstream, attempt, run, run_attempt=1):
        return {'GITHUB_SHA':'a'*40,'ATLAS_UPSTREAM_RUN':str(upstream),'ATLAS_UPSTREAM_ATTEMPT':str(attempt),
                'GITHUB_RUN_ID':str(run),'GITHUB_RUN_ATTEMPT':str(run_attempt)}

    def test_matrix_preserves_original_candidate_and_binds_current_attempt(self):
        with patch.object(workflow,'ROOT',self.root), patch.dict(os.environ,self.environment(12,2,20,3)):
            result = workflow.update_context('benchmark_cases')
        self.assertEqual(result['candidate_run_id'],12)
        self.assertEqual(result['candidate_run_attempt'],2)
        self.assertEqual(result['benchmark_cases_run_id'],20)
        self.assertEqual(result['benchmark_cases_run_attempt'],3)

    def test_join_restores_original_candidate_then_preview_restores_join(self):
        with patch.object(workflow,'ROOT',self.root), patch.dict(os.environ,self.environment(20,3,21,2)):
            joined = workflow.update_context('benchmark')
        self.assertEqual(joined['candidate_run_id'],12)
        self.assertEqual(joined['benchmark_cases_run_id'],20)
        with patch.object(workflow,'ROOT',self.root), patch.dict(os.environ,self.environment(21,2,22)):
            preview = workflow.update_context('preview')
        self.assertEqual(preview['candidate_run_id'],12)
        self.assertEqual(preview['benchmark_run_id'],21)
        self.assertEqual(preview['preview_run_id'],22)

    def test_wrong_checkpoint_attempt_head_or_unexpected_context_is_rejected(self):
        for changed in ({**self.candidate,'candidate_run_attempt':1}, {**self.candidate,'head_sha':'b'*40},
                        {**self.candidate,'source_name':'private'}, {**self.candidate,'format_version':1}):
            self.path.write_text(json.dumps(changed))
            with self.subTest(changed=changed), patch.object(workflow,'ROOT',self.root), \
                    patch.dict(os.environ,self.environment(12,2,20)), self.assertRaises(ContractError):
                workflow.update_context('benchmark_cases')

    def test_case_verifies_current_source_before_and_after_the_actual_measurement(self):
        with patch.object(workflow,'ROOT',self.root), patch.dict(os.environ,self.environment(12,2,20)), \
                patch.object(workflow,'original_candidate'), patch.object(workflow,'run') as run:
            workflow.benchmark_case('warm_changed',2)
        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual([command[1] for command in commands],
                         ['tools/hosted/candidate.py','verify-production','tools/hosted/production-build.py',
                          'tools/hosted/candidate.py','verify-production'])
        self.assertIn('--case',commands[2])
        self.assertIn('warm_changed',commands[2])
        self.assertNotIn('-clock',commands[1])
        self.assertNotIn('-clock',commands[-1])

    def test_relay_dispatch_is_after_strict_completed_context_without_private_secrets(self):
        with patch.object(workflow,'context',return_value=(12,2)) as context, \
                patch.object(workflow.subprocess,'run') as run:
            run.return_value.returncode = 0
            workflow.dispatch_benchmarks()
        context.assert_called_once_with('benchmark_dispatch',None)
        self.assertEqual(json.loads(run.call_args.kwargs['input']),{'ref':'main','inputs':{'upstream_run_id':'12'}})
        with patch.object(workflow,'context',side_effect=ContractError('upstream in progress')), \
                patch.object(workflow.subprocess,'run') as run, self.assertRaises(ContractError):
            workflow.dispatch_benchmarks()
        run.assert_not_called()

    def test_cleanup_removes_partial_replay_workspaces_and_rejects_links(self):
        replay = self.root/'build-private/benchmark-123/workspace/.atlas-private'
        replay.mkdir(parents=True)
        (replay/'state-seal.key').write_bytes(b'private')
        opened=self.root/'atlas-open-123';opened.mkdir();(opened/'identity').write_bytes(b'private')
        transferred=self.root/'atlas-transfer-123';transferred.mkdir();(transferred/'checkpoint.tar.gz').write_bytes(b'private')
        with patch.object(workflow,'ROOT',self.root): workflow.cleanup_private()
        self.assertFalse(replay.exists())
        self.assertFalse(opened.exists())
        self.assertFalse(transferred.exists())
        self.assertFalse(self.path.exists())
        (self.root/'.atlas-private').symlink_to(self.root/'build-private',target_is_directory=True)
        with patch.object(workflow,'ROOT',self.root), self.assertRaises(ContractError): workflow.cleanup_private()
