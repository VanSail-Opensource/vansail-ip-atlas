"""Authenticate completed benchmark jobs and bounded source-free artifacts."""
from __future__ import annotations
from datetime import datetime
import re

from tools.release_contract.contracts import ContractError, sha256
from tools.release_contract.acceptance import BUILD_SCENARIOS

MATRIX_WORKFLOW = '.github/workflows/production-benchmarks.yml'
JOIN_WORKFLOW = '.github/workflows/production-benchmark-join.yml'
CASE_MEMBERS = {'production-build-case.json', 'runner-budget.json'}


def positive(value):
    if type(value) is not int or not 0 < value < 10**20:
        raise ContractError('invalid hosted producer identity')
    return value


def timestamp(value):
    if not isinstance(value, str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', value):
        raise ContractError('invalid hosted completion clock')
    try:
        return int(datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp())
    except (ValueError, OverflowError):
        raise ContractError('invalid hosted completion clock') from None


def api_object(ci, route):
    from tools.release_contract.promotion import json_object
    return json_object(ci._get(route))


def collect_cases(ci, run_id, head):
    """Require the complete successful matrix run, never an in-progress join."""
    from tools.release_contract.promotion import extract_reports
    run_id = positive(run_id)
    run = ci.run(run_id, head, MATRIX_WORKFLOW)
    if run.get('id') != run_id:
        raise ContractError('benchmark run identity changed')
    attempt = positive(run.get('run_attempt'))
    completed = timestamp(run.get('updated_at'))
    listing = api_object(ci, f'actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100')
    jobs = listing.get('jobs')
    expected = {f'benchmark-{scenario}-{sample}': (scenario, sample)
                for scenario in BUILD_SCENARIOS for sample in (1, 2, 3)}
    if type(jobs) is not list or len(jobs) != 15 or listing.get('total_count') != 15:
        raise ContractError('exactly fifteen current-attempt benchmark jobs are required')
    bound_jobs = {}
    for job in jobs:
        if (type(job) is not dict or job.get('name') not in expected or job['name'] in bound_jobs
                or job.get('run_id') != run_id or job.get('run_attempt') != attempt
                or job.get('head_sha') != head or job.get('status') != 'completed'
                or job.get('conclusion') != 'success' or type(job.get('labels')) is not list
                or 'ubuntu-24.04' not in job['labels'] or 'self-hosted' in job['labels']):
            raise ContractError('benchmark job is not successful exact-attempt hosted evidence')
        positive(job.get('id'))
        if not timestamp(job.get('started_at')) <= timestamp(job.get('completed_at')) <= completed:
            raise ContractError('benchmark job completion does not bind its producer')
        bound_jobs[job['name']] = job
    listing = api_object(ci, f'actions/runs/{run_id}/artifacts?per_page=100')
    artifacts = listing.get('artifacts')
    if (type(artifacts) is not list or type(listing.get('total_count')) is not int
            or listing['total_count'] != len(artifacts) or len(artifacts) > 100):
        raise ContractError('bounded complete benchmark artifact listing required')
    prefix = f'atlas-build-case-{attempt}-'
    matches = [a for a in artifacts if isinstance(a, dict) and str(a.get('name', '')).startswith(prefix)]
    if len(matches) != 15:
        raise ContractError('exactly fifteen current-attempt benchmark artifacts are required')
    by_name = {}
    for artifact in matches:
        if artifact['name'] in by_name:
            raise ContractError('duplicate current-attempt benchmark artifact')
        by_name[artifact['name']] = artifact
    cases = []
    seen_ids = set()
    for job_name, (scenario, sample) in expected.items():
        name = f'{prefix}{scenario}-{sample}'
        artifact = by_name.get(name, {})
        artifact_id = positive(artifact.get('id'))
        if artifact_id in seen_ids:
            raise ContractError('benchmark artifact reused across cases')
        seen_ids.add(artifact_id)
        metadata = api_object(ci, f'actions/artifacts/{artifact_id}')
        job = bound_jobs[job_name]
        for value in (artifact, metadata):
            if (value.get('id') != artifact_id or value.get('name') != name or value.get('expired') is not False
                    or value.get('workflow_run', {}).get('id') != run_id
                    or value.get('workflow_run', {}).get('head_sha') != head
                    or type(value.get('size_in_bytes')) is not int or not 0 < value['size_in_bytes'] <= 16 * 1024**2
                    or not re.fullmatch(r'sha256:[0-9a-f]{64}', str(value.get('digest', '')))
                    or not timestamp(job['started_at']) <= timestamp(value.get('created_at')) <= timestamp(job['completed_at'])):
                raise ContractError('benchmark artifact does not bind the completed case job')
        if metadata['digest'] != artifact['digest'] or metadata['size_in_bytes'] != artifact['size_in_bytes']:
            raise ContractError('benchmark artifact metadata changed')
        data = ci._get(f'actions/artifacts/{artifact_id}/zip')
        if len(data) != metadata['size_in_bytes'] or sha256(data) != metadata['digest'][7:]:
            raise ContractError('benchmark archive differs from its GitHub digest')
        reports = extract_reports(data, CASE_MEMBERS)
        cases.append({'case_report': reports['production-build-case.json'],
                      'budget_report': reports['runner-budget.json'],
                      'provenance': {'run_id': run_id, 'run_attempt': attempt,
                          'job_id': job['id'], 'job_name': job_name, 'artifact_id': artifact_id,
                          'artifact_sha256': sha256(data),
                          'case_report_sha256': sha256(reports['production-build-case.json']),
                          'budget_report_sha256': sha256(reports['runner-budget.json'])}})
    final = ci.run(run_id, head, MATRIX_WORKFLOW)
    if final.get('id') != run_id or final.get('run_attempt') != attempt:
        raise ContractError('benchmark attempt changed during artifact verification')
    return final, cases


def candidate_reports(ci, run_id, attempt, head):
    """Fetch exactly the frozen candidate's original two evidence members."""
    run_id, attempt = positive(run_id), positive(attempt)
    run = ci.run(run_id, head, '.github/workflows/production-candidate.yml')
    if run.get('id') != run_id or run.get('run_attempt') != attempt:
        raise ContractError('candidate attempt changed after benchmark binding')
    listing = api_object(ci, f'actions/runs/{run_id}/artifacts?per_page=100')
    values = listing.get('artifacts')
    if type(values) is not list or listing.get('total_count') != len(values) or len(values) > 100:
        raise ContractError('bounded complete candidate artifact listing required')
    matches = [v for v in values if v.get('name') == 'production-candidate-evidence' and v.get('expired') is False]
    if len(matches) != 1:
        raise ContractError('candidate evidence artifact is ambiguous')
    value = matches[0]
    if (not re.fullmatch(r'sha256:[0-9a-f]{64}', str(value.get('digest', '')))
            or not timestamp(run.get('run_started_at')) <= timestamp(value.get('created_at')) <= timestamp(run.get('updated_at'))):
        raise ContractError('candidate evidence does not bind the current attempt')
    reports = ci.reports('candidate', run_id, positive(value.get('id')), value['digest'][7:], head)
    final = ci.run(run_id, head, '.github/workflows/production-candidate.yml')
    if final.get('id') != run_id or final.get('run_attempt') != attempt:
        raise ContractError('candidate attempt changed during artifact verification')
    return final, reports
