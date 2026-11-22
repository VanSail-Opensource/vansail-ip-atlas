"""Closed source-free evidence for fifteen independent real-input benchmarks.

GitHub job/artifact authentication belongs to benchmark_transport. This module
binds the exact bytes it supplies, recomputes all measurements and never opens
private state or treats a caller's success flag as evidence.
"""
from __future__ import annotations

import copy
import json
import re

from tools.release_contract.acceptance import BUILD_SCENARIOS, CORPUS_STRATA, allocation_gate, build_gates, require_all, valid_ipv4_coverage
from tools.release_contract.contracts import ContractError, NATIVE_LOOKUP_P95_LIMIT_NS, canonical_bytes, sha256

CASE_SCOPE = 'hosted-production-build-case-v1'
BUILD_SCOPE = 'hosted-production-build-v2'
MEASUREMENT_SCOPE = 'authenticated-real-input-engineering-benchmark'
ENVELOPE = {'scope': 'github-hosted-cgroup-v2', 'cpu_quota_us': 200000, 'cpu_period_us': 100000,
            'memory_max_bytes': 8 * 1024**3, 'swap_max_bytes': 0, 'workspace_limit_bytes': 14 * 1024**3}
RESOURCE_ACCOUNTING = {'scope': 'entire-child-process-group', 'poll_ms': 100,
    'scratch_scope': 'all-baseline-inputs-and-isolated-replay-output',
    'blind_spots': 'procfs-between-poll-peaks; cgroup peak recorded separately'}
LIMIT_CONTRACT = {'schema_version': 1, 'execution_envelope': ENVELOPE,
    'runtime_ms': {name: (35 if name == 'cold_full' else 3 if name == 'warm_unchanged' else 8) * 60000 for name in BUILD_SCENARIOS},
    'rss_bytes': 6656 * 1024**2, 'scratch_bytes': 10240 * 1024**2, 'disk_reserve_bytes': 1024**3,
    'lookup_p95_ns': NATIVE_LOOKUP_P95_LIMIT_NS, 'lookup_samples': 100000, 'lookup_warmups': 10000,
    'corpus_queries': 10000, 'samples_per_case': 3, 'gomaxprocs': 2, 'gomemlimit_bytes': 5 * 1024**3}
DIGEST_KEYS = {'release_id', 'candidate_bundle_sha256', 'qualification_receipt_sha256', 'normalized_state_sha256',
    'source_catalog_sha256', 'rights_audit_sha256', 'normalization_config_sha256', 'implementation_sha256',
    'certification_sha256', 'source_capabilities_sha256', 'benchmark_plan_sha256', 'limit_contract_sha256'}
IDENTITY_KEYS = DIGEST_KEYS | {'head_sha', 'candidate_run_id', 'candidate_run_attempt', 'evaluated_at', 'valid_until'}
CASE_KEYS = {'schema_version', 'scope', 'mode', 'errors', 'identity', 'producer', 'execution_host', 'scenarios'}
ROW_KEYS = {'scenario', 'sample', 'measurement_scope', 'runtime_ms', 'clock', 'process_group_peak_rss_bytes',
    'scratch_peak_bytes', 'physical_free_low_water_bytes', 'allocation_count', 'allocated_bytes',
    'allocation_process_count', 'allocation_scope', 'go_processes', 'go_invocations', 'allocation_exclusions',
    'input_records', 'normalized_input_bytes', 'before_state_sha256', 'after_state_sha256', 'release_id', 'compile_exit_code', 'transition'}
TRANSITION_KEYS = {'before_records', 'after_records', 'added_records', 'removed_records', 'changed_records',
                   'expired_sources_retracted', 'withdrawn_sources_retracted'}
PROVENANCE_KEYS = {'run_id', 'run_attempt', 'job_id', 'job_name', 'artifact_id', 'artifact_sha256',
                   'case_report_sha256', 'budget_report_sha256'}


def fail():
    raise ContractError('invalid bound production benchmark evidence')


def keys(value, expected):
    if type(value) is not dict or set(value) != expected:
        fail()
    return value


def integer(value, minimum=0, maximum=2**53-1):
    if type(value) is not int or not minimum <= value <= maximum:
        fail()
    return value


def digest(value):
    if type(value) is not str or re.fullmatch('[0-9a-f]{64}', value) is None:
        fail()
    return value


def json_report(data, maximum=16*1024**2):
    if type(data) is not bytes or not 0 < len(data) <= maximum:
        fail()
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                fail()
            result[key] = value
        return result
    try:
        value = json.loads(data.decode('utf-8'), object_pairs_hook=unique)
        canonical_bytes(value)  # Bounds integers, rejects floats/NaN and invalid Unicode.
    except (ValueError, UnicodeError, RecursionError):
        fail()
    return value


def benchmark_plan(identity):
    return {'version': 2, 'scope': MEASUREMENT_SCOPE, 'clock': identity['evaluated_at'],
        'baseline': identity['normalized_state_sha256'], 'scenarios': list(BUILD_SCENARIOS),
        'samples': 3, 'changed_records': 'max(1,ceil(N/100))'}


def validate_identity(identity):
    keys(identity, IDENTITY_KEYS)
    for key in DIGEST_KEYS:
        digest(identity[key])
    if type(identity['head_sha']) is not str or re.fullmatch('[0-9a-f]{40}', identity['head_sha']) is None:
        fail()
    for key in ('candidate_run_id', 'candidate_run_attempt'):
        integer(identity[key], 1)
    integer(identity['evaluated_at'], 1)
    integer(identity['valid_until'], identity['evaluated_at']+1)
    if (identity['benchmark_plan_sha256'] != sha256(canonical_bytes(benchmark_plan(identity)))
            or identity['limit_contract_sha256'] != sha256(canonical_bytes(LIMIT_CONTRACT))):
        fail()
    return identity


def benchmark_identity(candidate, receipt, *, head_sha, candidate_run_id, candidate_run_attempt):
    """Extract only approved aggregate bindings from the authenticated receipt."""
    try:
        if (candidate['mode'] != 'production' or receipt['mode'] != 'production'
                or receipt['release_scope'] != 'release-scope-v6'
                or candidate['qualification_receipt_sha256'] != sha256(canonical_bytes(receipt))
                or any(candidate[key] != receipt[key] for key in ('release_id', 'normalized_state_sha256', 'valid_until'))
                or candidate['valid_from'] != receipt['evaluated_at']):
            fail()
        value = {key: receipt[key] for key in DIGEST_KEYS - {'candidate_bundle_sha256', 'qualification_receipt_sha256', 'benchmark_plan_sha256', 'limit_contract_sha256'}}
        value.update({key: candidate[key] for key in ('candidate_bundle_sha256', 'qualification_receipt_sha256')})
        value.update(head_sha=head_sha, candidate_run_id=candidate_run_id, candidate_run_attempt=candidate_run_attempt,
                     evaluated_at=receipt['evaluated_at'], valid_until=receipt['valid_until'])
        value['benchmark_plan_sha256'] = sha256(canonical_bytes(benchmark_plan(value)))
        value['limit_contract_sha256'] = sha256(canonical_bytes(LIMIT_CONTRACT))
        return validate_identity(value)
    except (KeyError, TypeError):
        fail()


def host(value):
    keys(value, {'logical_cpus', 'memory_bytes', 'disk_bytes'})
    for field in value:
        integer(value[field], 1)
    return value


def validate_row(row, identity, scenario, sample):
    keys(row, ROW_KEYS)
    if (scenario not in BUILD_SCENARIOS or integer(sample, 1, 3) != sample
            or row['scenario'] != scenario or type(row['sample']) is not int or row['sample'] != sample
            or row['measurement_scope'] != MEASUREMENT_SCOPE
            or row['allocation_exclusions'] != 'non-Go orchestration and baseline preparation'
            or row['before_state_sha256'] != identity['normalized_state_sha256']
            or row['compile_exit_code'] != 0 or type(row['compile_exit_code']) is not int):
        fail()
    for field in ('before_state_sha256', 'after_state_sha256', 'release_id'):
        digest(row[field])
    for field in ('runtime_ms', 'process_group_peak_rss_bytes', 'scratch_peak_bytes',
                  'physical_free_low_water_bytes', 'input_records', 'normalized_input_bytes'):
        integer(row[field], 1)
    integer(row['clock'], identity['evaluated_at'])
    if (scenario == 'clock_advance') != (row['clock'] > identity['evaluated_at']):
        fail()
    if (row['runtime_ms'] >= LIMIT_CONTRACT['runtime_ms'][scenario]
            or row['process_group_peak_rss_bytes'] >= LIMIT_CONTRACT['rss_bytes']
            or row['scratch_peak_bytes'] >= LIMIT_CONTRACT['scratch_bytes']
            or row['physical_free_low_water_bytes'] < LIMIT_CONTRACT['disk_reserve_bytes']
            or allocation_gate(row) != 'passed'):
        fail()
    transition = keys(row['transition'], TRANSITION_KEYS)
    for value in transition.values():
        integer(value)
    before, after, added, removed, changed = (transition[key] for key in
        ('before_records', 'after_records', 'added_records', 'removed_records', 'changed_records'))
    if before + added - removed != after or row['input_records'] != (after if scenario == 'cold_full' else before):
        fail()
    if scenario == 'cold_full':
        valid = before == 0 and after > 0 and added == changed == after and removed == 0
    elif scenario == 'warm_unchanged':
        valid = before == after > 0 and added == removed == changed == 0 and row['before_state_sha256'] == row['after_state_sha256']
    elif scenario == 'warm_changed':
        valid = before == after > 0 and added == removed == changed == max(1, (before+99)//100)
    else:
        # Native withdrawal counts removed rows; Changed remains zero by design.
        valid = before > after >= 0 and removed > 0 and added == changed == 0
    if (not valid or (transition['expired_sources_retracted'] > 0) != (scenario == 'clock_advance')
            or (transition['withdrawn_sources_retracted'] > 0) != (scenario == 'withdrawal')):
        fail()
    return row


def case_report(identity, row, *, run_id, run_attempt, execution_host):
    value = {'schema_version': 1, 'scope': CASE_SCOPE, 'mode': 'production', 'errors': [],
        'identity': copy.deepcopy(identity), 'producer': {'run_id': run_id, 'run_attempt': run_attempt,
        'job_name': f"benchmark-{row['scenario']}-{row['sample']}"},
        'execution_host': copy.deepcopy(execution_host), 'scenarios': [copy.deepcopy(row)]}
    return validate_case_report(value, identity, run_id=run_id, run_attempt=run_attempt,
                                scenario=row['scenario'], sample=row['sample'])


def validate_case_report(report, identity, *, run_id, run_attempt, scenario, sample):
    validate_identity(identity)
    keys(report, CASE_KEYS)
    validate_identity(report['identity'])
    producer = {'run_id': integer(run_id, 1), 'run_attempt': integer(run_attempt, 1),
                'job_name': f'benchmark-{scenario}-{sample}'}
    if (report['schema_version'] != 1 or type(report['schema_version']) is not int
            or report['scope'] != CASE_SCOPE or report['mode'] != 'production' or report['errors'] != []
            or report['identity'] != identity or keys(report['producer'], set(producer)) != producer
            or type(report['scenarios']) is not list or len(report['scenarios']) != 1):
        fail()
    host(report['execution_host'])
    integer(report['producer']['run_id'], 1)
    integer(report['producer']['run_attempt'], 1)
    validate_row(report['scenarios'][0], identity, scenario, sample)
    canonical_bytes(report)
    return report


def validate_budget(report):
    keys(report, {'schema_version', 'execution_envelope', 'raw_host', 'workspace_peak_bytes',
        'physical_free_low_water_bytes', 'errors', 'exit_code', 'runtime_ms', 'cgroup_memory_peak_bytes', 'memory_events'})
    if (type(report['schema_version']) is not int or report['schema_version'] != 1
            or keys(report['execution_envelope'], set(ENVELOPE)) != ENVELOPE
            or report['errors'] != [] or type(report['exit_code']) is not int or report['exit_code'] != 0):
        fail()
    host(report['raw_host'])
    for field, expected in ENVELOPE.items():
        if type(expected) is int:
            integer(report['execution_envelope'][field])
    for field in ('workspace_peak_bytes', 'physical_free_low_water_bytes', 'runtime_ms', 'cgroup_memory_peak_bytes'):
        integer(report[field], 1)
    events = report['memory_events']
    required = {'low', 'high', 'max', 'oom', 'oom_kill', 'oom_group_kill'}
    if type(events) is not dict or not required <= set(events) <= required | {'sock_throttled'}:
        fail()
    for value in events.values():
        integer(value)
    if (any(events[key] for key in ('oom', 'oom_kill', 'oom_group_kill'))
            or report['workspace_peak_bytes'] >= ENVELOPE['workspace_limit_bytes'] - LIMIT_CONTRACT['disk_reserve_bytes']
            or report['physical_free_low_water_bytes'] < LIMIT_CONTRACT['disk_reserve_bytes']
            or report['cgroup_memory_peak_bytes'] > ENVELOPE['memory_max_bytes']):
        fail()
    return report


def verify_native_lookup(candidate, native_report):
    """Recompute the unchanged strict 2us p95 gate from all 100000 timings."""
    report = keys(native_report, {'index_page_reads', 'index_preparation', 'timing', 'corpus_queries', 'warmups', 'corpus_sha256', 'release_id',
        'corpus_ipv4_network_coverage', 'compressed_input_bytes', 'samples_ns', 'p50_ns', 'p95_ns', 'p99_ns', 'allocation_count', 'allocated_bytes',
        'process_peak_rss_bytes', 'temporary_disk_bytes', 'runtime_ns', 'go_version', 'object_reads', 'strata'})
    if (not valid_ipv4_coverage(report['corpus_ipv4_network_coverage']) or report['release_id'] != candidate.get('release_id') or report['timing'] != 'individual-indexed-lookups'
            or type(report['corpus_queries']) is not int or report['corpus_queries'] != 10000
            or type(report['warmups']) is not int or report['warmups'] != 10000
            or not isinstance(report['go_version'], str) or re.fullmatch(r'go[0-9]+\.[0-9]+\.[0-9]+', report['go_version']) is None):
        fail()
    digest(report['release_id']); digest(report['corpus_sha256'])
    for field in ('compressed_input_bytes', 'allocation_count', 'allocated_bytes', 'process_peak_rss_bytes', 'temporary_disk_bytes', 'runtime_ns'):
        integer(report[field])
    preparation = keys(report['index_preparation'], {'runtime_ns', 'allocated_bytes', 'allocation_count', 'source_object_reads'})
    for value in preparation.values():
        integer(value)
    if report['temporary_disk_bytes'] >= LIMIT_CONTRACT['scratch_bytes']:
        fail()
    samples = report['samples_ns']
    if type(samples) is not list or len(samples) != 100000:
        fail()
    for value in samples:
        integer(value)
    ordered = sorted(samples)
    for rank in (50, 95, 99):
        if integer(report[f'p{rank}_ns']) != ordered[1000*rank-1]:
            fail()
    for counter in ('object_reads', 'index_page_reads'):
        reads = keys(report[counter], {'before_warmup', 'after_warmup', 'before_timed', 'after_timed', 'warmup', 'timed'})
        for value in reads.values():
            integer(value)
        if (not reads['before_warmup'] <= reads['after_warmup'] <= reads['before_timed'] <= reads['after_timed']
                or reads['warmup'] != reads['after_warmup']-reads['before_warmup']
                or reads['timed'] != reads['after_timed']-reads['before_timed']):
            fail()
    strata = report['strata']
    if type(strata) is not list or len(strata) != len(CORPUS_STRATA):
        fail()
    for name, row in zip(CORPUS_STRATA, strata):
        keys(row, {'stratum', 'corpus_queries', 'timed_samples', 'p50_ns', 'p95_ns', 'p99_ns'})
        if row['stratum'] != name or integer(row['timed_samples']) != 10*integer(row['corpus_queries']):
            fail()
        if row['timed_samples']:
            values = [integer(row[f'p{rank}_ns']) for rank in (50, 95, 99)]
            if values != sorted(values):
                fail()
        elif any(row[f'p{rank}_ns'] is not None for rank in (50, 95, 99)):
            fail()
    if sum(row['corpus_queries'] for row in strata) != 10000 or report['p95_ns'] >= NATIVE_LOOKUP_P95_LIMIT_NS:
        fail()
    return report['p95_ns']


def aggregate_reports(candidate, native_lookup_bytes, cases, *, identity, benchmark_run_id, benchmark_run_attempt):
    """Join evidence from a completed MATRIX producer, not the join workflow."""
    validate_identity(identity)
    integer(benchmark_run_id, 1); integer(benchmark_run_attempt, 1)
    if any(candidate.get(key) != identity[key] for key in ('release_id', 'candidate_bundle_sha256', 'qualification_receipt_sha256', 'normalized_state_sha256')):
        fail()
    native = json_report(native_lookup_bytes)
    verify_native_lookup(candidate, native)
    if type(cases) is not list or len(cases) != 15:
        fail()
    bound, seen, jobs, artifacts = [], set(), set(), set()
    for entry in cases:
        keys(entry, {'case_report', 'budget_report', 'provenance'})
        provenance = keys(entry['provenance'], PROVENANCE_KEYS)
        for field in ('run_id', 'run_attempt', 'job_id', 'artifact_id'):
            integer(provenance[field], 1)
        for field in ('artifact_sha256', 'case_report_sha256', 'budget_report_sha256'):
            digest(provenance[field])
        if (provenance['run_id'] != benchmark_run_id or provenance['run_attempt'] != benchmark_run_attempt
                or provenance['job_id'] in jobs or provenance['artifact_id'] in artifacts):
            fail()
        jobs.add(provenance['job_id']); artifacts.add(provenance['artifact_id'])
        for field in ('case_report', 'budget_report'):
            if type(entry[field]) is not bytes or sha256(entry[field]) != provenance[field+'_sha256']:
                fail()
        report, budget = json_report(entry['case_report'], 128*1024), json_report(entry['budget_report'], 16*1024)
        if type(provenance['job_name']) is not str:
            fail()
        match = re.fullmatch(r'benchmark-('+'|'.join(BUILD_SCENARIOS)+r')-([123])', provenance['job_name'])
        if match is None or (match[1], int(match[2])) in seen:
            fail()
        scenario, sample = match[1], int(match[2]); seen.add((scenario, sample))
        validate_case_report(report, identity, run_id=benchmark_run_id, run_attempt=benchmark_run_attempt, scenario=scenario, sample=sample)
        validate_budget(budget)
        if report['execution_host'] != budget['raw_host'] or budget['runtime_ms'] < report['scenarios'][0]['runtime_ms']:
            fail()
        bound.append({'case_report': report, 'budget_report': budget, 'provenance': copy.deepcopy(provenance)})
    bound.sort(key=lambda entry: (BUILD_SCENARIOS.index(entry['case_report']['scenarios'][0]['scenario']), entry['case_report']['scenarios'][0]['sample']))
    report = {'schema_version': 2, 'scope': BUILD_SCOPE, 'mode': 'production', 'errors': [],
        'identity': copy.deepcopy(identity), 'benchmark_run_id': benchmark_run_id, 'benchmark_run_attempt': benchmark_run_attempt,
        'benchmark_cases': bound, 'execution_envelopes': [{'scenario': entry['case_report']['scenarios'][0]['scenario'],
            'sample': entry['case_report']['scenarios'][0]['sample'], 'budget_report': entry['budget_report']} for entry in bound],
        'scenarios': [entry['case_report']['scenarios'][0] for entry in bound], 'measurement_scope': MEASUREMENT_SCOPE,
        'resource_accounting': copy.deepcopy(RESOURCE_ACCOUNTING), 'go_lookup': native,
        'native_lookup_sha256': sha256(native_lookup_bytes)}
    report.update({key: identity[key] for key in ('release_id', 'candidate_bundle_sha256', 'qualification_receipt_sha256', 'normalized_state_sha256', 'benchmark_plan_sha256')})
    report['derived_gates'] = build_gates(report)
    require_all(report['derived_gates'])
    canonical_bytes(report)
    return report
