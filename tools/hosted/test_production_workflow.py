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
        (self.private / 'workflow-context.json').write_text(json.dumps({'integration_run_id': 10}))
        self.environment = {'ATLAS_UPSTREAM_RUN': '11', 'GITHUB_RUN_ID': '12', 'GITHUB_SHA': 'a' * 40}

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
        self.assertTrue(any('tools/hosted/production-build.py' in command for command in commands))
        self.assertEqual(commands[-1], ['python', 'tools/hosted/candidate.py', '--public', 'web/.output/public'])
        self.assertEqual(json.loads((self.private / 'workflow-context.json').read_text()), {
            'integration_run_id': 10, 'intake_run_id': 11, 'candidate_run_id': 12, 'head_sha': 'a' * 40})

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
                    'conclusion': 'success', 'event': 'push'}
        with patch.dict(os.environ, env), patch.object(workflow, 'api', side_effect=api), \
                patch.object(workflow.time, 'monotonic', side_effect=[0, 3600]), \
                patch.object(workflow.time, 'sleep'):
            workflow.context('intake', None)
        self.assertEqual(output.read_text(), 'upstream_run_id=11\n')
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
