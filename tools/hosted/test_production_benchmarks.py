import copy
import unittest

from tools.hosted import production_benchmarks as b
from tools.release_contract.acceptance import build_gates
from tools.release_contract.contracts import ContractError, canonical_bytes, sha256


def fixture():
    receipt = {key: 'a'*64 for key in b.DIGEST_KEYS - {'candidate_bundle_sha256', 'qualification_receipt_sha256', 'benchmark_plan_sha256', 'limit_contract_sha256'}}
    receipt.update(mode='production', release_scope='release-scope-v6', evaluated_at=100, valid_until=1000,
                   included_sources=[{'private': 'never-public'}])
    candidate = {'mode': 'production', 'release_id': receipt['release_id'], 'normalized_state_sha256': receipt['normalized_state_sha256'],
        'candidate_bundle_sha256': 'b'*64, 'qualification_receipt_sha256': sha256(canonical_bytes(receipt)),
        'valid_from': 100, 'valid_until': 1000}
    identity = b.benchmark_identity(candidate, receipt, head_sha='c'*40, candidate_run_id=50, candidate_run_attempt=2)
    host = {'logical_cpus': 4, 'memory_bytes': 16*1024**3, 'disk_bytes': 80*1024**3}
    budget = {'schema_version': 1, 'execution_envelope': copy.deepcopy(b.ENVELOPE), 'raw_host': host,
        'workspace_peak_bytes': 1024**3, 'physical_free_low_water_bytes': 4*1024**3, 'errors': [], 'exit_code': 0,
        'runtime_ms': 2000, 'cgroup_memory_peak_bytes': 1024**3,
        'memory_events': {key: 0 for key in ('low', 'high', 'max', 'oom', 'oom_kill', 'oom_group_kill')}}
    native = {'index_preparation': dict(runtime_ns=100, allocated_bytes=300, allocation_count=1, source_object_reads=1), 'timing': 'individual-indexed-lookups', 'corpus_queries': 10000, 'warmups': 10000,
        'corpus_sha256': 'd'*64, 'corpus_ipv4_network_coverage': None, 'release_id': candidate['release_id'], 'compressed_input_bytes': 1,
        'samples_ns': [1000]*100000, 'p50_ns': 1000, 'p95_ns': 1000, 'p99_ns': 1000,
        'allocation_count': 1, 'allocated_bytes': 1, 'process_peak_rss_bytes': 1, 'temporary_disk_bytes': 0,
        'runtime_ns': 100000000, 'go_version': 'go1.27.4',
        'index_page_reads':dict(before_warmup=0,after_warmup=1,before_timed=1,after_timed=3,warmup=1,timed=2),
        'object_reads': dict(before_warmup=1, after_warmup=2, before_timed=2, after_timed=2, warmup=1, timed=0),
        'strata': [{'stratum': name, 'corpus_queries': 5000 if name in ('ipv4_exact', 'unknown') else 0,
            'timed_samples': 50000 if name in ('ipv4_exact', 'unknown') else 0,
            **{f'p{rank}_ns': 1000 if name in ('ipv4_exact', 'unknown') else None for rank in (50,95,99)}} for name in b.CORPUS_STRATA]}
    cases = []
    for index, (scenario, sample) in enumerate((name, sample) for name in b.BUILD_SCENARIOS for sample in (1,2,3)):
        token = f'{index:032x}'
        transition = dict(before_records=100, after_records=100, added_records=0, removed_records=0,
            changed_records=0, expired_sources_retracted=0, withdrawn_sources_retracted=0)
        if scenario == 'cold_full':
            transition.update(before_records=0, added_records=100, changed_records=100)
        elif scenario == 'warm_changed':
            transition.update(added_records=1, removed_records=1, changed_records=1)
        elif scenario in ('clock_advance', 'withdrawal'):
            transition.update(after_records=90, removed_records=10)
            transition['expired_sources_retracted' if scenario == 'clock_advance' else 'withdrawn_sources_retracted'] = 1
        row = dict(scenario=scenario, sample=sample, measurement_scope=b.MEASUREMENT_SCOPE, runtime_ms=1000,
            clock=1000 if scenario == 'clock_advance' else 100, process_group_peak_rss_bytes=1024,
            scratch_peak_bytes=1024, physical_free_low_water_bytes=4*1024**3, allocation_count=10, allocated_bytes=100,
            allocation_process_count=1, allocation_scope='all-atlas-Go-processes-in-scenario',
            go_processes=[dict(allocated_bytes=100, allocation_count=10, command='benchmark-state', exit_code=0,
                invocation=token, pid=123, schema_version=1, scope='atlas-go-runtime-allocations-v1')],
            go_invocations=[dict(invocation=token, phase='benchmark-state', root_pid=123, exit_code=0, expected_commands={'benchmark-state':1})],
            allocation_exclusions='non-Go orchestration and baseline preparation', input_records=100, normalized_input_bytes=1000,
            before_state_sha256='a'*64, after_state_sha256='a'*64 if scenario == 'warm_unchanged' else 'e'*64,
            release_id='f'*64, compile_exit_code=0, transition=transition)
        case = b.case_report(identity, row, run_id=60, run_attempt=3, execution_host=host)
        case_bytes, budget_bytes = canonical_bytes(case), canonical_bytes(budget)
        cases.append({'case_report': case_bytes, 'budget_report': budget_bytes,
            'provenance': dict(run_id=60, run_attempt=3, job_id=100+index, job_name=f'benchmark-{scenario}-{sample}',
                artifact_id=200+index, artifact_sha256=f'{index:064x}', case_report_sha256=sha256(case_bytes), budget_report_sha256=sha256(budget_bytes))})
    return candidate, receipt, identity, native, cases


class BenchmarkEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.candidate, self.receipt, self.identity, self.native, self.cases = fixture()

    def aggregate(self, cases=None, native=None):
        return b.aggregate_reports(self.candidate, canonical_bytes(self.native if native is None else native),
            self.cases if cases is None else cases, identity=self.identity, benchmark_run_id=60, benchmark_run_attempt=3)

    def mutate(self, cases, index, field, change):
        value = b.json_report(cases[index][field]); change(value)
        cases[index][field] = canonical_bytes(value)
        cases[index]['provenance'][field+'_sha256'] = sha256(cases[index][field])

    def test_complete_join_is_deterministic_source_free_and_recomputes_all_gates(self):
        report = self.aggregate()
        self.assertEqual(report['benchmark_run_id'], 60)
        self.assertEqual(report['benchmark_run_attempt'], 3)
        self.assertEqual(len(report['execution_envelopes']), 15)
        self.assertEqual(set(report['derived_gates'].values()), {'passed'})
        self.assertEqual(report, self.aggregate(list(reversed(self.cases))))
        self.assertNotIn(b'never-public', canonical_bytes(report))
        self.assertNotIn(b'included_sources', canonical_bytes(report))
        self.assertEqual(report['native_lookup_sha256'], sha256(canonical_bytes(self.native)))

    def test_identity_binds_receipt_candidate_plan_limits_and_run(self):
        for field in ('release_id', 'normalized_state_sha256', 'valid_until', 'qualification_receipt_sha256'):
            candidate = copy.deepcopy(self.candidate); candidate[field] = 99 if field == 'valid_until' else 'e'*64
            with self.subTest(field=field), self.assertRaises(ContractError):
                b.benchmark_identity(candidate, self.receipt, head_sha='c'*40, candidate_run_id=50, candidate_run_attempt=2)
        for field in ('benchmark_plan_sha256', 'limit_contract_sha256'):
            identity = copy.deepcopy(self.identity); identity[field] = 'f'*64
            with self.subTest(field=field), self.assertRaises(ContractError):
                b.validate_identity(identity)

    def test_missing_duplicate_and_cross_attempt_cases_are_rejected(self):
        variants = [self.cases[:-1], [*self.cases[:-1], self.cases[0]]]
        for field, value in (('run_attempt', 2), ('run_id', 61), ('job_id', 101), ('artifact_id', 201), ('job_name', 'benchmark-cold_full-2')):
            cases = copy.deepcopy(self.cases); cases[0]['provenance'][field] = value; variants.append(cases)
        for cases in variants:
            with self.subTest(case_count=len(cases)), self.assertRaises(ContractError):
                self.aggregate(cases)

    def test_exact_raw_bytes_and_closed_report_schemas(self):
        cases = copy.deepcopy(self.cases); cases[0]['case_report'] += b'\n'
        with self.assertRaises(ContractError): self.aggregate(cases)
        for field in ('case_report', 'budget_report'):
            cases = copy.deepcopy(self.cases)
            self.mutate(cases, 0, field, lambda value: value.update(source_url='private'))
            with self.subTest(field=field), self.assertRaises(ContractError): self.aggregate(cases)
        with self.assertRaises(ContractError): b.json_report(b'{"x":1,"x":2}')
        with self.assertRaises(ContractError): b.json_report(b'{"x":NaN}')

    def test_every_final_budget_is_required_and_checked(self):
        changes = [lambda v: v['memory_events'].update(oom=1), lambda v: v['memory_events'].update(oom_kill=1),
            lambda v: v.update(errors=['failed']), lambda v: v.update(exit_code=1),
            lambda v: v.update(runtime_ms=1), lambda v: v.update(runtime_ms=True),
            lambda v: v.update(workspace_peak_bytes=13*1024**3),
            lambda v: v['execution_envelope'].update(swap_max_bytes=False),
            lambda v: v['execution_envelope'].update(cpu_quota_us=400000),
            lambda v: v.update(cgroup_memory_peak_bytes=8*1024**3+1),
            lambda v: v.update(physical_free_low_water_bytes=1024**3-1)]
        for change in changes:
            cases = copy.deepcopy(self.cases); self.mutate(cases, 14, 'budget_report', change)
            with self.subTest(change=change), self.assertRaises(ContractError): self.aggregate(cases)
        report = self.aggregate(); report['execution_envelopes'].pop()
        self.assertEqual(build_gates(report)['standard_runner'], 'unmeasured')
        report = self.aggregate(); report['execution_envelopes'][14]['budget_report']['memory_events']['oom'] = 1
        self.assertEqual(build_gates(report)['standard_runner'], 'unmeasured')

    def test_closed_case_boundaries_and_original_strict_runtime_limits(self):
        changes = [lambda v: v['identity'].update(candidate_run_attempt=1),
            lambda v: v['producer'].update(run_attempt=True),
            lambda v: v['scenarios'][0].update(runtime_ms=35*60000),
            lambda v: v['scenarios'][0].update(clock=101),
            lambda v: v['scenarios'][0]['transition'].update(after_records=101),
            lambda v: v['scenarios'][0]['go_processes'][0].update(allocated_bytes=99),
            lambda v: v['scenarios'][0].update(source_id='private')]
        for change in changes:
            cases = copy.deepcopy(self.cases); self.mutate(cases, 0, 'case_report', change)
            with self.subTest(change=change), self.assertRaises(ContractError): self.aggregate(cases)

    def test_native_lookup_recomputes_percentiles_and_rejects_equality(self):
        self.assertEqual(b.verify_native_lookup(self.candidate, self.native), 1000)
        for change in (lambda v: v.update(p95_ns=999), lambda v: v.update(release_id='f'*64),
                       lambda v: v.update(warmups=9999), lambda v: v.update(source_name='private')):
            native = copy.deepcopy(self.native); change(native)
            with self.subTest(change=change), self.assertRaises(ContractError): self.aggregate(native=native)
        native = copy.deepcopy(self.native)
        native.update(samples_ns=[2000]*100000, p50_ns=2000, p95_ns=2000, p99_ns=2000)
        with self.assertRaises(ContractError): self.aggregate(native=native)


if __name__ == '__main__':
    unittest.main()
