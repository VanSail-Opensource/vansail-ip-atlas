import copy
import io
import json
import stat
import unittest
import zipfile
from unittest.mock import patch

from tools.hosted import benchmark_transport as transport
from tools.release_contract.acceptance import BUILD_SCENARIOS
from tools.release_contract.contracts import ContractError, sha256
from tools.release_contract.promotion import TrustedCI


def archive(case, budget):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as zipped:
        for name, data in [('production-build-case.json', case), ('runner-budget.json', budget)]:
            info = zipfile.ZipInfo(name)
            info.external_attr = (stat.S_IFREG | 0o600) << 16
            zipped.writestr(info, data)
    return output.getvalue()


class BenchmarkTransportTests(unittest.TestCase):
    def setUp(self):
        self.head = 'a'*40
        self.run = {'id': 60, 'run_attempt': 3, 'head_sha': self.head, 'head_branch': 'main',
            'head_repository': {'full_name': 'VanSail-Opensource/vansail-ip-atlas'},
            'path': transport.MATRIX_WORKFLOW, 'event': 'workflow_dispatch', 'status': 'completed',
            'conclusion': 'success', 'updated_at': '2026-11-15T02:00:00Z'}
        self.jobs, self.artifacts, self.archives = [], [], {}
        for index, (scenario, sample) in enumerate((s, n) for s in BUILD_SCENARIOS for n in (1, 2, 3)):
            self.jobs.append({'id': 100+index, 'run_id': 60, 'run_attempt': 3, 'head_sha': self.head,
                'name': f'benchmark-{scenario}-{sample}', 'status': 'completed', 'conclusion': 'success',
                'labels': ['ubuntu-24.04'], 'started_at': '2026-11-15T01:00:00Z', 'completed_at': '2026-11-15T01:50:00Z'})
            data = archive(json.dumps({'case': index}).encode(), b'{"budget":true}')
            self.archives[200+index] = data
            self.artifacts.append({'id': 200+index, 'name': f'atlas-build-case-3-{scenario}-{sample}',
                'expired': False, 'workflow_run': {'id': 60, 'head_sha': self.head},
                'size_in_bytes': len(data), 'digest': 'sha256:'+sha256(data), 'created_at': '2026-11-15T01:49:00Z'})
        self.routes = []

    def request(self, route):
        self.routes.append(route)
        if route == 'actions/runs/60': return json.dumps(self.run).encode()
        if route == 'actions/runs/60/attempts/3/jobs?per_page=100':
            return json.dumps({'total_count': len(self.jobs), 'jobs': self.jobs}).encode()
        if route == 'actions/runs/60/artifacts?per_page=100':
            return json.dumps({'total_count': len(self.artifacts), 'artifacts': self.artifacts}).encode()
        if route.startswith('actions/artifacts/'):
            artifact = int(route.split('/')[2])
            if route.endswith('/zip'): return self.archives[artifact]
            return json.dumps(next(a for a in self.artifacts if a['id'] == artifact)).encode()
        raise AssertionError(route)

    def collect(self):
        ci = TrustedCI()
        with patch.object(ci, '_get', side_effect=self.request):
            return transport.collect_cases(ci, 60, self.head)

    def test_all_fifteen_jobs_and_original_archive_bytes_are_bound(self):
        run, cases = self.collect()
        self.assertEqual(run['run_attempt'], 3)
        self.assertEqual(len(cases), 15)
        self.assertIn('actions/runs/60/attempts/3/jobs?per_page=100', self.routes)
        self.assertFalse(any(route == 'actions/runs/60/jobs' for route in self.routes))
        for case in cases:
            proof = case['provenance']
            self.assertEqual(proof['case_report_sha256'], sha256(case['case_report']))
            self.assertEqual(proof['budget_report_sha256'], sha256(case['budget_report']))
            self.assertEqual(proof['artifact_sha256'], sha256(self.archives[proof['artifact_id']]))

    def test_run_must_be_completed_successful_same_head_main_workflow(self):
        baseline = copy.deepcopy(self.run)
        for changes in ({'status': 'in_progress'}, {'conclusion': 'failure'}, {'head_sha': 'b'*40},
                        {'path': '.github/workflows/production-candidate.yml'}, {'head_branch': 'feature'},
                        {'run_attempt': True}):
            self.run = {**baseline, **changes}
            with self.subTest(changes=changes), self.assertRaises(ContractError): self.collect()

    def test_current_attempt_requires_exact_successful_job_population(self):
        original = copy.deepcopy(self.jobs)
        for change in ({'status': 'in_progress'}, {'conclusion': 'failure'}, {'run_attempt': 2},
                       {'run_id': 61}, {'head_sha': 'b'*40}, {'name': original[1]['name']},
                       {'labels': ['self-hosted', 'ubuntu-24.04']}, {'completed_at': '2026-11-15T03:00:00Z'}):
            self.jobs = copy.deepcopy(original); self.jobs[0].update(change)
            with self.subTest(change=change), self.assertRaises(ContractError): self.collect()
        for jobs in (original[:-1], original+[original[0]]):
            self.jobs = jobs
            with self.assertRaises(ContractError): self.collect()

    def test_artifact_attempt_name_origin_timestamp_and_digest_are_bound(self):
        original = copy.deepcopy(self.artifacts)
        for change in ({'name': 'atlas-build-case-2-cold_full-1'}, {'name': original[1]['name']},
                       {'expired': True}, {'workflow_run': {'id': 61, 'head_sha': self.head}},
                       {'created_at': '2026-11-15T00:00:00Z'}, {'digest': 'sha256:'+'f'*64},
                       {'size_in_bytes': 20*1024**2}):
            self.artifacts = copy.deepcopy(original); self.artifacts[0].update(change)
            with self.subTest(change=change), self.assertRaises(ContractError): self.collect()
        self.artifacts = original
        self.archives[200] += b'changed'
        with self.assertRaises(ContractError): self.collect()

    def test_prior_attempt_artifact_cannot_substitute_but_is_not_current_case(self):
        old = copy.deepcopy(self.artifacts[0]); old.update(id=999, name='atlas-build-case-2-cold_full-1')
        self.artifacts.append(old)
        self.assertEqual(len(self.collect()[1]), 15)
        self.artifacts.pop(0)
        with self.assertRaises(ContractError): self.collect()

    def test_rerun_started_during_artifact_download_invalidates_the_join(self):
        ci=TrustedCI()
        def changed(route):
            result=self.request(route)
            if route.endswith('/214/zip'):
                self.run.update(run_attempt=4,status='in_progress',conclusion=None)
            return result
        with patch.object(ci,'_get',side_effect=changed),self.assertRaises(ContractError):
            transport.collect_cases(ci,60,self.head)

    def test_missing_or_unexpected_archive_member_blocks_evidence(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as zipped:
            zipped.writestr('production-build-case.json', b'{}')
            zipped.writestr('private-source.json', b'{}')
        self.archives[200] = stream.getvalue()
        self.artifacts[0].update(size_in_bytes=len(stream.getvalue()), digest='sha256:'+sha256(stream.getvalue()))
        with self.assertRaises(ContractError): self.collect()


if __name__ == '__main__': unittest.main()
