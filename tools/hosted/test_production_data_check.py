import json
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.hosted import production_data_check as check
from tools.hosted.production_data_check import verify_lookup_measurement
from tools.release_contract.contracts import ContractError


class ActualLookupGateTests(unittest.TestCase):
    def report(self, value):
        return {'timing': 'individual-indexed-lookups', 'corpus_queries': 10000,
                'warmups': 10000, 'samples_ns': [value] * 100000, 'p95_ns': value}

    def test_original_strict_ceiling_and_observed_percentile(self):
        self.assertEqual(verify_lookup_measurement(self.report(1999)), 1999)
        with self.assertRaises(ContractError):
            verify_lookup_measurement(self.report(2000))
        report = self.report(2500)
        report['p95_ns'] = 1999
        with self.assertRaises(ContractError):
            verify_lookup_measurement(report)

    def test_missing_or_non_integer_observations_cannot_pass(self):
        for mutate in (lambda value: value['samples_ns'].pop(),
                       lambda value: value['samples_ns'].__setitem__(0, True),
                       lambda value: value.update(corpus_queries=1)):
            report = self.report(1000)
            mutate(report)
            with self.assertRaises(ContractError):
                verify_lookup_measurement(report)

    def test_main_writes_canonical_success_and_failure_reports(self):
        for lookup_ns, passed in ((1999, True), (2000, False)):
            with self.subTest(passed=passed), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                def run(argv):
                    if argv[0] == 'go':
                        path = Path(argv[-1])
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_text(json.dumps(self.report(lookup_ns)))
                with patch.object(check, 'ROOT', root), patch.object(check, 'run', side_effect=run), \
                     patch.object(check, 'intake_clock', return_value=1794733697), \
                     patch.object(check.time, 'monotonic_ns', side_effect=(0, 1000001)):
                    if passed:
                        check.main()
                    else:
                        with self.assertRaises(ContractError):
                            check.main()
                report = json.loads((root / 'reports/production-data-check.json').read_bytes())
                self.assertIs(report['passed'], passed)
                self.assertEqual(report['compile_runtime_ms'], 2)
                self.assertIs(type(report['compile_runtime_ms']), int)
                self.assertEqual(report['observed_input'], {'status': 'unavailable'})
                self.assertEqual(report['compile_counters'], [])

    def test_compile_failure_retains_elapsed_time_and_only_current_phase_diagnostics(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private = root / '.atlas-private'
            private.mkdir()
            log = private / 'stage.log'
            old = 'ATLAS_COMPILE_PHASE ' + json.dumps({'phase': 'history', 'event': 'begin', 'elapsed_ms': 0, 'ok': True}) + '\n'
            log.write_text(old)
            row = {'phase': 'qualification', 'event': 'begin', 'elapsed_ms': 0, 'ok': True}
            def run(_):
                with log.open('a') as stream:
                    stream.write('private source marker\nATLAS_COMPILE_PHASE ' + json.dumps(row) + '\n')
                raise ContractError('compile failed')
            with patch.object(check, 'ROOT', root), patch.object(check, 'run', side_effect=run), \
                 patch.object(check, 'intake_clock', return_value=1794733697), \
                 patch.object(check.time, 'monotonic_ns', side_effect=(0, 2100000000000)), \
                 self.assertRaises(ContractError):
                check.main()
            report = json.loads((root / 'reports/production-data-check.json').read_bytes())
            self.assertFalse(report['passed'])
            self.assertEqual(report['compile_runtime_ms'], 2100000)
            self.assertEqual(report['compile_phases'], [row])

    def test_failed_compile_reports_only_current_bounded_counters_and_stops(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private = root / '.atlas-private'
            private.mkdir()
            log = private / 'stage.log'
            row = {'phase': 'pipeline-partition', 'input_records': 200, 'unique_records': 150,
                   'sort_runs': 17, 'partitions': 4, 'binary_byte_repacks': 2,
                   'sort_buffer_peak': 4096, 'partition_buffer_peak': 1024,
                   'output_bytes': 2048, 'scratch_peak': 8192,
                   'objects_by_kind': [0, 0, 0, 18498] + [0] * 9 + [1]}
            encode = lambda value: 'ATLAS_COMPILE_COUNTERS ' + json.dumps(value) + '\n'
            log.write_text(encode({**row, 'phase': 'pipeline-publish'}))
            def run(_):
                with log.open('a') as stream:
                    stream.write('PRIVATE_SOURCE\n' + encode({**row, 'source': 'PRIVATE_SOURCE'}) + encode(row))
                raise ContractError('compile failed')
            with patch.object(check, 'ROOT', root), patch.object(check, 'run', side_effect=run) as execute, \
                    patch.object(check, 'intake_clock', return_value=1794733697), \
                    patch.object(check.time, 'monotonic_ns', side_effect=(0, 2100000000000)), \
                    self.assertRaises(ContractError):
                check.main()
            execute.assert_called_once()
            report_bytes = (root / 'reports/production-data-check.json').read_bytes()
            report = json.loads(report_bytes)
            self.assertFalse(report['passed'])
            self.assertEqual(report['compile_runtime_ms'], 2100000)
            self.assertEqual(report['compile_counters'], [row])
            self.assertNotIn(b'PRIVATE_SOURCE', report_bytes)
            self.assertNotIn('lookup_p95_ns', report)


class ObservedInputDiagnosticTests(unittest.TestCase):
    clock = 1794096000

    def fixture(self):
        stamp = lambda value: datetime.fromtimestamp(value, timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        parts = [{'SHA256': [1] * 32, 'Bytes': 128, 'Records': 10,
                  'Codec': 'zstd-v1', 'DecodedBytes': 1024},
                 {'SHA256': [2] * 32, 'Bytes': 256, 'Records': 20,
                  'Codec': 'zstd-v1', 'DecodedBytes': 2048}]
        state = {'Version': 2, 'EvaluatedAt': stamp(self.clock), 'PolicyHash': [3] * 32,
                 'Sources': [{'ID': 'PRIVATE_SOURCE_MARKER', 'Fingerprint': [4] * 32,
                              'ExpiresAt': stamp(self.clock + 3600), 'Records': None,
                              'RecordPartitions': parts,
                              'Receipt': {'private': 'https://private.invalid/secret'}},
                             {'ID': 'OTHER_PRIVATE_SOURCE', 'Fingerprint': [5] * 32,
                              'ExpiresAt': stamp(self.clock + 3600), 'Records': [],
                              'RecordPartitions': [dict(parts[0])]}]}
        report = {'schema_version': 1, 'scope': 'actual-source-intake-not-production-acceptance',
                  'evaluated_at': self.clock, 'configured_sources': 2, 'active_sources': 2,
                  'current_sources': 2, 'all_active_current': True, 'production_eligible': False,
                  'blocked_reason_counts': {}, 'source_catalog_sha256': 'a' * 64}
        return state, report

    def write(self, root, state, report):
        (root / '.atlas-private').mkdir(exist_ok=True)
        (root / 'reports').mkdir(exist_ok=True)
        data = json.dumps(state).encode()
        (root / '.atlas-private/state-v1.json').write_bytes(data)
        report = dict(report, normalized_state_sha256=sha256(data).hexdigest())
        (root / 'reports/source-intake.json').write_text(json.dumps(report))

    def test_valid_compressed_reference_sums_are_source_free(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write(root, *self.fixture())
            result = check.observed_input_diagnostics(root, self.clock + 1)
            self.assertEqual(result, {'status': 'available', 'normalized_records': 40,
                                     'partition_references': 3, 'stored_bytes': 512, 'decoded_bytes': 4096})
            encoded = json.dumps(result)
            for private in ('PRIVATE', 'secret', 'https:', 'SHA256', 'RecordPartitions', directory):
                self.assertNotIn(private, encoded)

    def test_hash_mismatch_missing_and_duplicate_json_are_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertEqual(check.observed_input_diagnostics(root, self.clock), {'status': 'unavailable'})
            self.write(root, *self.fixture())
            path = root / '.atlas-private/state-v1.json'
            path.write_bytes(path.read_bytes() + b' ')
            self.assertEqual(check.observed_input_diagnostics(root, self.clock), {'status': 'unavailable'})
            self.write(root, *self.fixture())
            report = root / 'reports/source-intake.json'
            report.write_text(report.read_text().replace('{', '{"schema_version":1,', 1))
            self.assertEqual(check.observed_input_diagnostics(root, self.clock), {'status': 'unavailable'})

    def test_malformed_partition_counters_and_unsupported_storage_are_unavailable(self):
        for key, value in [('Records', True), ('Records', 1.0), ('Records', '10'),
                           ('Records', 0), ('Records', 100001), ('Bytes', -1),
                           ('Bytes', 7), ('Bytes', (64 << 20) + 1),
                           ('DecodedBytes', None), ('DecodedBytes', (64 << 20) + 1),
                           ('Codec', ''), ('Codec', 'unknown'), ('SHA256', [True] * 32),
                           ('SHA256', [0] * 32)]:
            with self.subTest(key=key, value=value), tempfile.TemporaryDirectory() as directory:
                state, report = self.fixture()
                state['Sources'][0]['RecordPartitions'][0][key] = value
                root = Path(directory)
                self.write(root, state, report)
                self.assertEqual(check.observed_input_diagnostics(root, self.clock), {'status': 'unavailable'})

    def test_unsuccessful_or_expired_intake_and_inline_records_are_unavailable(self):
        for target, key, value in [('report', 'all_active_current', False),
                                   ('report', 'current_sources', True),
                                   ('report', 'blocked_reason_counts', {'private': 1}),
                                   ('report', 'evaluated_at', self.clock + 1),
                                   ('state', 'Version', True), ('state', 'Version', 1),
                                   ('source', 'ExpiresAt', '2020-01-01T00:00:00Z'),
                                   ('source', 'Records', [{'private': 'raw-record'}])]:
            with self.subTest(target=target, key=key), tempfile.TemporaryDirectory() as directory:
                state, report = self.fixture()
                {'report': report, 'state': state, 'source': state['Sources'][0]}[target][key] = value
                root = Path(directory)
                self.write(root, state, report)
                self.assertEqual(check.observed_input_diagnostics(root, self.clock), {'status': 'unavailable'})
