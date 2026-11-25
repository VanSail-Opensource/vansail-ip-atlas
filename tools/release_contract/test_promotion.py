import copy
import io
import json
import stat
import unittest
from unittest.mock import patch
import zipfile

from tools.release_contract.contracts import ContractError, sha256
from tools.release_contract.promotion import REPOSITORY, TrustedCI, extract_reports, json_object, verify_corpus_binding


def archive(entries):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as bundle:
        for name, data, mode in entries:
            entry = zipfile.ZipInfo(name)
            entry.external_attr = mode << 16
            bundle.writestr(entry, data)
    return output.getvalue()


class TrustedEvidenceTests(unittest.TestCase):
    def test_browser_and_native_measurements_bind_the_same_actual_corpus(self):
        digest = 'a' * 64
        coverage = {'covered_addresses': 2**32, 'network_objects': 1, 'router_intervals': 2}
        for proof in (None, coverage):
            report = {'corpus_sha256': digest, 'corpus_ipv4_network_coverage': proof}
            verify_corpus_binding(report, {'go_lookup': report})
        with self.assertRaises(ContractError):
            verify_corpus_binding({'corpus_sha256': digest, 'corpus_ipv4_network_coverage': None},
                                  {'go_lookup': {'corpus_sha256': digest, 'corpus_ipv4_network_coverage': coverage}})
        for browser, build in (({}, {}), ({}, {'go_lookup': {}}),
                               ({'corpus_sha256': 'b' * 64}, {'go_lookup': {'corpus_sha256': digest}})):
            with self.subTest(browser=browser, build=build), self.assertRaises(ContractError):
                verify_corpus_binding(browser, build)

    def test_source_free_archive_allowlist_and_regular_files_are_exact(self):
        regular = stat.S_IFREG | 0o644
        data = archive([("report.json", b'{"raw":1}', regular)])
        self.assertEqual(extract_reports(data, {"report.json"}), {"report.json": b'{"raw":1}'})
        for entries in ([('../report.json', b'{}', regular)], [('report.json', b'{}', stat.S_IFLNK | 0o777)],
                        [('report.json', b'{}', regular), ('sources.yaml', b'private', regular)],
                        [('report.json', b'{}', regular), ('report.json', b'{}', regular)]):
            with self.subTest(entries=entries), self.assertRaises(ContractError):
                extract_reports(archive(entries), {"report.json"})

    def test_duplicate_and_nonfinite_report_fields_fail(self):
        for data in (b'{"status":"failed","status":"passed"}', b'{"time":NaN}', b'[]'):
            with self.subTest(data=data), self.assertRaises(ContractError):
                json_object(data)

    def test_exact_head_successful_main_workflow_and_repository_are_independent(self):
        head = "a" * 40
        good = {"status": "completed", "conclusion": "success", "head_sha": head, "head_branch": "main",
                "event": "workflow_dispatch", "path": ".github/workflows/production-candidate.yml",
                "head_repository": {"full_name": REPOSITORY}}
        ci = TrustedCI()
        with patch.object(ci, "_get", return_value=json.dumps(good).encode()):
            self.assertEqual(ci.run(1, head, good["path"]), good)
        for change in ({"conclusion": "failure"}, {"status": "in_progress"}, {"head_sha": "b" * 40},
                       {"head_branch": "feature"}, {"event": "pull_request"}, {"path": ".github/workflows/untrusted.yml"},
                       {"head_repository": {"full_name": "another/repository"}}):
            with self.subTest(change=change), patch.object(ci, "_get", return_value=json.dumps({**good, **change}).encode()), self.assertRaises(ContractError):
                ci.run(1, head, good["path"])

    def test_api_digest_size_originating_run_and_archive_bytes_are_bound(self):
        ci = TrustedCI()
        data = archive([(name, b'{}', stat.S_IFREG | 0o644) for name in ("static-candidate.json", "production-lookup.json")])
        digest, head = sha256(data), "a" * 40
        metadata = {"name": "production-candidate-evidence", "expired": False, "workflow_run": {"id": 1, "head_sha": head},
                    "digest": "sha256:" + digest, "size_in_bytes": len(data)}
        def request(route):
            return data if route.endswith('/zip') else json.dumps(metadata).encode()
        with patch.object(ci, "run"), patch.object(ci, "_get", side_effect=request):
            self.assertEqual(set(ci.reports("candidate", 1, 2, digest, head)), {"static-candidate.json", "production-lookup.json"})
        for field, value in (("expired", True), ("size_in_bytes", len(data) + 1), ("digest", "sha256:" + "0" * 64),
                             ("workflow_run", {"id": 9, "head_sha": head}), ("name", "private-sources")):
            changed = {**metadata, field: value}
            with self.subTest(field=field), patch.object(ci, "run"), patch.object(ci, "_get", side_effect=lambda route: data if route.endswith('/zip') else json.dumps(changed).encode()), self.assertRaises(ContractError):
                ci.reports("candidate", 1, 2, digest, head)


if __name__ == "__main__":
    unittest.main()

class ParallelPromotionRevalidationTests(unittest.TestCase):
    def test_reconstructs_all_fifteen_original_cases_and_rejects_changed_evidence(self):
        import copy
        import tempfile
        from pathlib import Path
        from tools.hosted.test_production_benchmarks import fixture
        from tools.hosted.production_benchmarks import aggregate_reports
        from tools.release_contract.contracts import canonical_bytes
        from tools.release_contract.promotion import verify_parallel_benchmarks
        candidate, receipt, identity, native, cases = fixture()
        native_bytes = canonical_bytes(native)
        build = aggregate_reports(candidate,native_bytes,cases,identity=identity,benchmark_run_id=60,benchmark_run_attempt=3)
        original = {'static-candidate.json':canonical_bytes(candidate),'production-lookup.json':native_bytes}
        reports = {**original,'production-build.json':canonical_bytes(build)}
        packet = {'head_sha':'c'*40,'assembled_at':200,'artifacts':[{'kind':'candidate','run_id':50,'run_attempt':2}]}
        matrix = {'id':60,'run_attempt':3,'updated_at':'1970-01-01T00:02:00Z'}
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'receipt.json';path.write_bytes(canonical_bytes(receipt))
            with patch('tools.hosted.benchmark_transport.candidate_reports',return_value=({},original)), \
                    patch('tools.hosted.benchmark_transport.collect_cases',return_value=(matrix,cases)) as collect:
                verify_parallel_benchmarks(object(),packet,candidate,reports,[path])
                collect.assert_called_once_with(unittest.mock.ANY,60,'c'*40)
                changed=copy.deepcopy(build);changed['derived_gates']['cold_full_runtime']='unmeasured'
                with self.assertRaises(ContractError):
                    verify_parallel_benchmarks(object(),packet,candidate,{**reports,'production-build.json':canonical_bytes(changed)},[path])
                with self.assertRaises(ContractError):
                    verify_parallel_benchmarks(object(),packet,candidate,reports,[path,path])
            for altered in ((matrix,cases[:-1]),({**matrix,'run_attempt':4},cases),
                            ({**matrix,'updated_at':'1970-01-01T00:04:00Z'},cases)):
                with patch('tools.hosted.benchmark_transport.candidate_reports',return_value=({},original)), \
                        patch('tools.hosted.benchmark_transport.collect_cases',return_value=altered), self.assertRaises(ContractError):
                    verify_parallel_benchmarks(object(),packet,candidate,reports,[path])

    def test_api_allowlist_accepts_only_fixed_attempt_job_listing(self):
        from types import SimpleNamespace
        ci=TrustedCI()
        def request(args,**kwargs):
            kwargs['stdout'].write(b'{}')
            return SimpleNamespace(returncode=0)
        with patch('tools.release_contract.promotion.subprocess.run',side_effect=request):
            self.assertEqual(ci._get('actions/runs/60/attempts/3/jobs?per_page=100'),b'{}')
            self.assertEqual(ci._get('actions/runs/60/artifacts?per_page=100'),b'{}')
            for route in ('actions/runs/60/attempts/0/jobs?per_page=100',
                          'actions/runs/60/attempts/3/jobs?per_page=100&page=2','actions/runs/60/../../secrets'):
                with self.subTest(route=route),self.assertRaises(ContractError): ci._get(route)

class FinalProducerAttemptTests(unittest.TestCase):
    def test_all_producers_are_still_completed_at_exact_attempt_before_authorization(self):
        from tools.release_contract.promotion import verify_completed_producers
        from unittest.mock import Mock
        packet={'head_sha':'a'*40,'assembled_at':200,'integration_run_id':1,'integration_run_attempt':1,
            'artifacts':[{'kind':'candidate','run_id':2,'run_attempt':1},
                         {'kind':'benchmark','run_id':4,'run_attempt':2},
                         {'kind':'preview','run_id':5,'run_attempt':1}]}
        build={'benchmark_run_id':3,'benchmark_run_attempt':3}
        expected={1:1,2:1,3:3,4:2,5:1}
        ci=Mock()
        ci.run.side_effect=lambda run_id,*_: {'run_attempt':expected[run_id],'updated_at':'1970-01-01T00:02:00Z'}
        verify_completed_producers(ci,packet,build)
        self.assertEqual({call.args[0] for call in ci.run.call_args_list},set(expected))
        for run_id in expected:
            changed={**expected,run_id:expected[run_id]+1}
            ci.run.side_effect=lambda value,*_: {'run_attempt':changed[value],'updated_at':'1970-01-01T00:02:00Z'}
            with self.subTest(run_id=run_id),self.assertRaises(ContractError):
                verify_completed_producers(ci,packet,build)
