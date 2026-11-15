import json
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
                     patch.object(check, 'intake_clock', return_value='2026-11-15T08:00:00Z'), \
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
