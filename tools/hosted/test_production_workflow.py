import json
import contextlib
import io
import os
from pathlib import Path
import subprocess
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

    def test_every_browser_job_uses_the_verified_immutable_deployment(self):
        reports = self.root/'reports'
        reports.mkdir()
        identity = {'candidate_bundle_sha256':'b'*64, 'release_id':'d'*64}
        origin = 'https://1234abcd.atlas.pages.dev'
        deployed = dict(identity, status='verified', operation='preview', environment='preview',
                        head_sha=self.environment['GITHUB_SHA'], url=origin)
        (reports/'static-candidate.json').write_text(json.dumps(identity))
        with patch.object(workflow,'ROOT',self.root), patch.dict(os.environ,self.environment):
            path = reports/'pages-deployment.json'
            path.write_text(json.dumps(deployed))
            self.assertEqual(workflow.preview_origin(), origin)
            for field, value in (('status','failed'),('environment','production'),('operation','promote'),
                                 ('release_id','e'*64),('candidate_bundle_sha256','f'*64),
                                 ('head_sha','0'*40),('url','https://atlas.pages.dev')):
                path.write_text(json.dumps(dict(deployed, **{field:value})))
                with self.subTest(field=field), self.assertRaises(ContractError):
                    workflow.preview_origin()

    def test_pr_package_verifies_the_same_static_tree_with_its_own_real_receipt(self):
        with patch.object(workflow, 'ROOT', self.root), patch.object(workflow, 'run') as run:
            workflow.integration_package()
        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(commands[-2], ['python', 'tools/release_contract/prepare_static.py', '--atlas',
            self.root/'build-private/integration-production-atlas', '--qualification-receipt',
            self.private/'integration-production-receipt.json'])
        self.assertEqual(commands[-1], ['python', 'tools/hosted/candidate.py', '--public', 'web/.output/public'])

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
        label = b'FAIL: static candidate: forbidden public data string'
        log.write_bytes(previous + label + b'\n')
        self.assertEqual(workflow.failure_category(log, len(previous)), 'public-data-string')
        log.write_bytes(previous + label + b': private-value\n')
        self.assertEqual(workflow.failure_category(log, len(previous)), 'command-failed')

    def test_pages_failure_category_is_exact_current_and_pages_only(self):
        log = self.private / 'stage.log'
        marker = b'ATLAS_PAGES_FAILURE asset-upload http-503'
        previous = b'ATLAS_PAGES_FAILURE qualification contract\n'
        start = len(previous)
        for data in (marker + b'\n', b'noisy\n' + b'x'*70000 + b'\n' + marker + b'\r\n'):
            log.write_bytes(previous + data)
            self.assertEqual(workflow.failure_category(log, start, phase='pages-deployment'), 'pages-asset-upload-http-503')
            self.assertEqual(workflow.failure_category(log, start, phase='compile-production'), 'command-failed')
        for malformed in (
            b'no new marker\n', marker, marker + b' body-and-token\n', b'fake source line\r' + marker + b'\n',
            b'ATLAS_PAGES_FAILURE http://private-input http-503\n', b'ATLAS_PAGES_FAILURE asset-upload http-999\n',
            b'ATLAS_PAGES_FAILURE asset-upload arbitrary-exception-message\n',
            b'x'*100 + marker + b'\n' + b'x'*(65536-len(marker)-1),
        ):
            with self.subTest(malformed=malformed[:100]):
                log.write_bytes(previous + malformed)
                self.assertEqual(workflow.failure_category(log, start, phase='pages-deployment'), 'command-failed')

    def test_failed_pages_child_exposes_no_command_or_response_details(self):
        private = 'example-private-body-path-and-bearer-token'
        public_out, public_err = io.StringIO(), io.StringIO()

        def failed_child(argv, **kwargs):
            kwargs['stderr'].write((private + '\nATLAS_PAGES_FAILURE asset-token network-timeout\n').encode())
            return subprocess.CompletedProcess(argv, 1)

        with (patch.object(workflow, 'ROOT', self.root), patch.object(workflow.subprocess, 'run', side_effect=failed_child),
              contextlib.redirect_stdout(public_out), contextlib.redirect_stderr(public_err), self.assertRaises(ContractError)):
            workflow.run(['python', 'tools/release_contract/pages.py', 'preview', private])
        self.assertEqual(public_out.getvalue(), 'Production step started: pages-deployment\n')
        self.assertEqual(public_err.getvalue(), 'Production step failed: pages-deployment\n'
                         'Production failure category: pages-asset-token-network-timeout\n')
        self.assertIn(private, (self.private / 'stage.log').read_text())

    def test_browser_failure_category_rejects_stale_partial_and_opaque_inputs(self):
        log = self.private / 'stage.log'
        phase = 'measure-production-browser'
        previous = b'ATLAS_BROWSER_FAILURE overview 4 contract\n'
        marker = b'ATLAS_BROWSER_FAILURE component-wheel-zoom 30 playwright-timeout'
        log.write_bytes(previous + b'x'*70000 + b'\n' + marker + b'\r\n')
        self.assertEqual(workflow.failure_category(log, len(previous), phase=phase),
                         'browser-component-wheel-zoom-sample-30-playwright-timeout')
        self.assertEqual(workflow.failure_category(log, len(previous), phase='pages-deployment'), 'command-failed')
        for malformed in (
            b'prior marker is not a current observation\n', marker, marker + b' private?q=source\n',
            b'outside-record\r' + marker + b'\n', b'ATLAS_BROWSER_FAILURE overview 31 contract\n',
            b'ATLAS_BROWSER_FAILURE overview 01 contract\n', b'ATLAS_BROWSER_FAILURE overview - contract\n',
            b'ATLAS_BROWSER_FAILURE report-validation 1 report-validation\n',
            b'ATLAS_BROWSER_FAILURE overview 1 unlisted-error-text\n',
            b'ATLAS_BROWSER_FAILURE https://example.invalid 1 contract\n',
            b'x'*100 + marker + b'\n' + b'z'*(65536-len(marker)-1),
        ):
            with self.subTest(malformed=malformed[:100]):
                log.write_bytes(previous + malformed)
                self.assertEqual(workflow.failure_category(log, len(previous), phase=phase), 'command-failed')
        log.write_bytes(b'ATLAS_BROWSER_FAILURE report-validation - report-validation\n')
        self.assertEqual(workflow.failure_category(log, 0, phase=phase), 'browser-report-validation-report-validation')

    def test_failed_browser_child_logs_only_route_sample_and_failure_class(self):
        private = 'https://example.invalid/path?query=private-source'
        public_out, public_err = io.StringIO(), io.StringIO()

        def failed_child(argv, **kwargs):
            kwargs['stderr'].write((private + '\nATLAS_BROWSER_FAILURE class-c 1 contract\n').encode())
            return subprocess.CompletedProcess(argv, 1)

        with (patch.object(workflow, 'ROOT', self.root), patch.object(workflow.subprocess, 'run', side_effect=failed_child),
              contextlib.redirect_stdout(public_out), contextlib.redirect_stderr(public_err), self.assertRaises(ContractError)):
            workflow.run(['node', 'tools/hosted/production-browser.mjs', private])
        self.assertEqual(public_out.getvalue(), 'Production step started: measure-production-browser\n')
        self.assertEqual(public_err.getvalue(), 'Production step failed: measure-production-browser\n'
                         'Production failure category: browser-class-c-sample-1-contract\n')
        self.assertIn(private, (self.private / 'stage.log').read_text())

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

        # GitHub sends null rather than an empty object when an operator
        # dispatches intake without inputs. It still requires a completed
        # exact-main integration and preserves its actual retry attempt.
        event.write_text('{"inputs":null}')
        env['GITHUB_EVENT_NAME'] = 'workflow_dispatch'
        output.unlink()
        with patch.dict(os.environ, env), patch.object(workflow, 'api', side_effect=api):
            self.assertEqual(workflow.context('intake', None), (11, 1))
        self.assertEqual(output.read_text(), 'upstream_run_id=11\nupstream_run_attempt=1\n')
        self.assertEqual(polls, 3)
        for payload in ('{"inputs":[]}', '{"inputs":{"upstream_run_id":11}}', '{"inputs":{"upstream_run_id":""}}'):
            event.write_text(payload)
            with self.subTest(payload=payload), patch.dict(os.environ, env), \
                    patch.object(workflow, 'api', side_effect=api), self.assertRaises(ContractError):
                workflow.context('intake', None)


class CompilePhaseDiagnosticsTests(unittest.TestCase):
    def test_failed_rebuild_identifies_measured_phase_without_child_log(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            public_out, public_err = io.StringIO(), io.StringIO()
            begin = {'event': 'begin', 'elapsed_ms': 0, 'ok': True}
            rows = [{**begin, 'phase': 'benchmark-prepare'},
                    {'phase': 'benchmark-prepare', 'event': 'end', 'elapsed_ms': 1900, 'ok': True},
                    {**begin, 'phase': 'benchmark-measure'},
                    {**begin, 'phase': 'materialize-spatial'}]
            def execute(argv, **kwargs):
                for row in rows:
                    kwargs['stderr'].write(('ATLAS_COMPILE_PHASE ' + json.dumps(row) + '\n').encode())
                kwargs['stderr'].write(b'private-token-marker\nATLAS_COMPILE_PHASE {"truncated":')
                return workflow.subprocess.CompletedProcess(argv, 1)
            with patch.object(workflow, 'ROOT', root), patch.object(workflow.subprocess, 'run', side_effect=execute), \
                 contextlib.redirect_stdout(public_out), contextlib.redirect_stderr(public_err), \
                 self.assertRaises(ContractError):
                workflow.run(['python', 'tools/hosted/production-build.py'])
            output = public_out.getvalue() + public_err.getvalue()
            self.assertIn('phase ended: benchmark-prepare elapsed_ms=1900 ok=true', output)
            self.assertIn('phase entered: benchmark-measure', output)
            self.assertIn('phase entered: materialize-spatial', output)
            self.assertNotIn('private-token-marker', output)
            self.assertNotIn('truncated', output)

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


class CompileCounterDiagnosticsTests(unittest.TestCase):
    def row(self, **changes):
        return {'phase': 'pipeline-sort', 'input_records': 123, 'unique_records': 100,
                'sort_runs': 17, 'partitions': 2, 'binary_byte_repacks': 3,
                'sort_buffer_peak': 4096, 'partition_buffer_peak': 1024,
                'output_bytes': 2048, 'scratch_peak': 8192, 'objects_by_kind': [0] * 14, **changes}

    def encode(self, row):
        return b'ATLAS_COMPILE_COUNTERS ' + json.dumps(row).encode() + b'\n'

    def test_exact_counter_schema_and_safe_integer_endpoints(self):
        rows = [self.row(phase=phase) for phase in sorted(workflow.COMPILE_COUNTER_PHASES)]
        for endpoint in (0, 2**53 - 1):
            rows.append(self.row(**dict.fromkeys(workflow.COMPILE_COUNTER_FIELDS, endpoint)))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'stage.log'
            path.write_bytes(b''.join(map(self.encode, rows)))
            self.assertEqual(workflow.compile_counter_diagnostics(path, 0), rows)

    def test_object_vector_accepts_exact_total_and_each_kind_boundary(self):
        vectors = [[0] * 14, [17, 0, 18482] + [0] * 11, [1423] * 13 + [0]]
        for kind in range(14):
            vector = [0] * 14
            vector[kind] = 18499
            vectors.append(vector)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'stage.log'
            for vector in vectors:
                with self.subTest(vector=vector):
                    row = self.row(objects_by_kind=vector)
                    path.write_bytes(self.encode(row))
                    self.assertEqual(workflow.compile_counter_diagnostics(path, 0), [row])

    def test_object_vector_rejects_wrong_shape_types_range_and_total(self):
        invalid = [None, 0, True, 'PRIVATE_SOURCE', {}, [], [0] * 13, [0] * 15,
                   [18499, 1] + [0] * 12, [1424] * 13 + [0]]
        for kind in range(14):
            for value in (-1, 18500, True, False, 1.0, 'PRIVATE_SOURCE', None, [], {}, [0]):
                vector = [0] * 14
                vector[kind] = value
                invalid.append(vector)
        rows = [self.row(objects_by_kind=vector) for vector in invalid]
        rows.append({key: value for key, value in self.row().items() if key != 'objects_by_kind'})
        rows.append(self.row(objects_by_kind=[0] * 14, kind_names=['PRIVATE_SOURCE']))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'stage.log'
            for row in rows:
                with self.subTest(row=row):
                    path.write_bytes(self.encode(row) + self.encode(self.row()))
                    self.assertEqual(workflow.compile_counter_diagnostics(path, 0), [self.row()])

    def test_invalid_types_ranges_schema_and_private_fields_are_omitted(self):
        invalid = [[], None, True, 1, 'PRIVATE_SOURCE', {},
                   self.row(source='PRIVATE_SOURCE'), self.row(phase='PRIVATE_SOURCE'),
                   self.row(phase=[]), self.row(phase=True)]
        for field in workflow.COMPILE_COUNTER_FIELDS:
            invalid.append({key: value for key, value in self.row().items() if key != field})
            for value in (-1, 2**53, True, False, 1.0, 'PRIVATE_SOURCE', None, [], {}, float('nan'), float('inf')):
                invalid.append(self.row(**{field: value}))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'stage.log'
            for row in invalid:
                with self.subTest(row=row):
                    path.write_bytes(self.encode(row) + self.encode(self.row()))
                    self.assertEqual(workflow.compile_counter_diagnostics(path, 0), [self.row()])

    def test_duplicate_keys_trailing_data_and_malformed_frames_are_omitted(self):
        encoded = json.dumps(self.row()).encode()
        malformed = [b'{"phase":"PRIVATE_SOURCE",' + encoded[1:],
                     b'{"sort_runs":0,' + encoded[1:], b'{"objects_by_kind":[],' + encoded[1:],
                     encoded + b' {}', encoded + b' PRIVATE_SOURCE',
                     encoded.replace(b'"phase"', b'"\xffphase"'), b'{', b'[' * 1000,
                     b' ' * 1024 + encoded]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'stage.log'
            for payload in malformed:
                with self.subTest(payload=payload[:80]):
                    path.write_bytes(b'ATLAS_COMPILE_COUNTERS ' + payload + b'\n')
                    self.assertEqual(workflow.compile_counter_diagnostics(path, 0), [])
            path.write_bytes(b'PRIVATE_SOURCE ' + self.encode(self.row()))
            self.assertEqual(workflow.compile_counter_diagnostics(path, 0), [])
            path.write_bytes(self.encode(self.row())[:-1])
            self.assertEqual(workflow.compile_counter_diagnostics(path, 0), [])

    def test_current_command_tail_and_record_limits(self):
        old = self.encode(self.row(phase='pipeline-publish'))
        current = self.encode(self.row())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'stage.log'
            path.write_bytes(old + current)
            self.assertEqual(workflow.compile_counter_diagnostics(path, len(old)), [self.row()])
            for start in (-1, True, 1.0, len(old + current) + 1):
                self.assertEqual(workflow.compile_counter_diagnostics(path, start), [])
            path.write_bytes(old + b'x' * 70000 + b'\n' + current)
            self.assertEqual(workflow.compile_counter_diagnostics(path, 0), [self.row()])
            # A tail beginning inside a long private line must not invent a marker.
            path.write_bytes(b'private-prefix' + current + b'x' * (65536 - len(current)))
            self.assertEqual(workflow.compile_counter_diagnostics(path, 0), [])
            path.write_bytes(current * 8)
            self.assertEqual(workflow.compile_counter_diagnostics(path, 0), [self.row()] * 8)
            path.write_bytes(current * 9)
            self.assertEqual(workflow.compile_counter_diagnostics(path, 0), [])
            path.write_bytes(b'\n' * 4096 + current)
            self.assertEqual(workflow.compile_counter_diagnostics(path, 0), [])
            path.unlink()
            self.assertEqual(workflow.compile_counter_diagnostics(path, 0), [])

    def test_failed_compile_console_exposes_only_sanitized_counters(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private = root / '.atlas-private'
            private.mkdir()
            (private / 'stage.log').write_bytes(self.encode(self.row(phase='pipeline-publish')))
            public_out, public_err = io.StringIO(), io.StringIO()
            def execute(argv, **kwargs):
                kwargs['stderr'].write(b'PRIVATE_SOURCE\n')
                kwargs['stderr'].write(self.encode(self.row(source='PRIVATE_SOURCE')))
                kwargs['stderr'].write(self.encode(self.row()))
                return workflow.subprocess.CompletedProcess(argv, 1)
            with patch.object(workflow, 'ROOT', root), patch.object(workflow.subprocess, 'run', side_effect=execute), \
                    contextlib.redirect_stdout(public_out), contextlib.redirect_stderr(public_err), \
                    self.assertRaises(ContractError):
                workflow.run(['build-private/atlas', 'compile-production'])
            output = public_out.getvalue() + public_err.getvalue()
            self.assertNotIn('PRIVATE_SOURCE', output)
            self.assertNotIn('pipeline-publish', output)
            lines = [line for line in output.splitlines() if line.startswith('Production compiler counters: ')]
            self.assertEqual(len(lines), 1)
            self.assertEqual(json.loads(lines[0].removeprefix('Production compiler counters: ')), self.row())
            self.assertIn('PRIVATE_SOURCE', (private / 'stage.log').read_text())


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
