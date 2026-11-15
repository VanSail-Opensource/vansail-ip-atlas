"""Compile actual admitted data in integration; never package or deploy a site."""
from __future__ import annotations
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import re
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools.hosted.production_workflow import compile_counter_diagnostics, compile_phase_diagnostics, intake_clock, run
from tools.release_contract.contracts import ContractError, canonical_bytes
from tools.release_contract.production import read_private


def observed_input_diagnostics(root: Path, now: int | None = None):
    """Count referenced partition descriptors, never estimate or expose sources.

    This optional observation is available only for the successful intake's exact
    state bytes and evaluation clock, with every source still unexpired at the
    observation time. It does not authenticate partition contents or replace any
    compile/admission check. Bytes are summed per reference, not deduplicated
    physical disk usage. Legacy plain/inline storage is deliberately unavailable.
    """
    unavailable = {'status': 'unavailable'}

    def invalid():
        raise ValueError('invalid observed input diagnostic')

    def integer(value, minimum, maximum):
        if type(value) is not int or not minimum <= value <= maximum:
            invalid()
        return value

    def unique_object(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                invalid()
            value[key] = item
        return value

    def document(data):
        return json.loads(data, object_pairs_hook=unique_object,
                          parse_constant=lambda _: invalid())

    def timestamp(value, whole_seconds=False):
        fraction = '' if whole_seconds else r'(?:\.[0-9]{1,9})?'
        if type(value) is not str or not re.fullmatch(
                r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}' + fraction + 'Z', value):
            invalid()
        return datetime.fromisoformat(value.replace('Z', '+00:00'))

    try:
        now = integer(int(time.time()) if now is None else now, 0, 2**53 - 1)
        current = datetime.fromtimestamp(now, timezone.utc)
        intake = document(read_private(root / 'reports/source-intake.json', 64 << 10))
        if (type(intake) is not dict or type(intake.get('schema_version')) is not int
                or intake['schema_version'] != 1
                or intake.get('scope') != 'actual-source-intake-not-production-acceptance'
                or intake.get('all_active_current') is not True
                or intake.get('production_eligible') is not False
                or type(intake.get('blocked_reason_counts')) is not dict
                or intake['blocked_reason_counts']):
            invalid()
        active = integer(intake.get('active_sources'), 1, 1000)
        if integer(intake.get('current_sources'), 1, 1000) != active:
            invalid()
        integer(intake.get('configured_sources'), active, 1000)
        evaluated = integer(intake.get('evaluated_at'), 0, now)
        for key in ('normalized_state_sha256', 'source_catalog_sha256'):
            if type(intake.get(key)) is not str or not re.fullmatch('[0-9a-f]{64}', intake[key]):
                invalid()
        data = read_private(root / '.atlas-private/state-v1.json', 64 << 20)
        if sha256(data).hexdigest() != intake['normalized_state_sha256']:
            invalid()
        state = document(data)
        if (type(state) is not dict or type(state.get('Version')) is not int or state['Version'] != 2
                or type(state.get('Sources')) is not list or len(state['Sources']) != active
                or int(timestamp(state.get('EvaluatedAt'), True).timestamp()) != evaluated):
            invalid()
        records = references = stored = decoded = 0
        for source in state['Sources']:
            if (type(source) is not dict or source.get('Records') not in (None, [])
                    or timestamp(source.get('ExpiresAt')) <= current):
                invalid()
            parts = source.get('RecordPartitions', [])
            if type(parts) is not list or len(parts) > 16384:
                invalid()
            for part in parts:
                if (type(part) is not dict
                        or set(part) != {'SHA256', 'Bytes', 'Records', 'Codec', 'DecodedBytes'}
                        or part['Codec'] != 'zstd-v1'):
                    invalid()
                digest = part['SHA256']
                if (type(digest) is not list or len(digest) != 32
                        or any(type(value) is not int or not 0 <= value <= 255 for value in digest)
                        or not any(digest)):
                    invalid()
                records += integer(part['Records'], 1, 100000)
                stored += integer(part['Bytes'], 8, 64 << 20)
                decoded += integer(part['DecodedBytes'], 8, 64 << 20)
                references += 1
        if max(records, references, stored, decoded) > 2**53 - 1:
            invalid()
        return {'status': 'available', 'normalized_records': records,
                'partition_references': references, 'stored_bytes': stored, 'decoded_bytes': decoded}
    except (ContractError, OSError, ValueError, OverflowError, RecursionError):
        return unavailable


def verify_lookup_measurement(report):
    if (type(report) is not dict or report.get('timing') != 'individual-indexed-lookups'
            or report.get('corpus_queries') != 10000 or report.get('warmups') != 10000):
        raise ContractError('actual indexed lookup population is incomplete')
    samples = report.get('samples_ns')
    if (type(samples) is not list or len(samples) != 100000
            or any(type(value) is not int or value < 0 for value in samples)):
        raise ContractError('actual indexed lookup samples are incomplete')
    p95 = sorted(samples)[94999]
    if type(report.get('p95_ns')) is not int or report['p95_ns'] != p95:
        raise ContractError('indexed lookup percentile differs from observations')
    if p95 >= 2000:
        raise ContractError('indexed lookup exceeds the original two-microsecond ceiling')
    return p95


def main():
    private = ROOT / '.atlas-private'
    atlas = ROOT / 'build-private/integration-production-atlas'
    receipt = private / 'integration-production-receipt.json'
    corpus = private / 'integration-production-corpus.json'
    report_path = ROOT / 'reports/production-data-check.json'
    report = {'schema_version': 1, 'scope': 'actual-data-compile-not-release', 'passed': False}
    report['observed_input'] = observed_input_diagnostics(ROOT)
    try:
        started = time.monotonic_ns()
        log = private / 'stage.log'
        log_start = log.stat().st_size if log.exists() else 0
        try:
            run(['build-private/atlas', 'compile-production', '-workspace', ROOT,
                 '-clock', intake_clock(), '-out', atlas, '-receipt', receipt])
        finally:
            report['compile_runtime_ms'] = (time.monotonic_ns() - started + 999999) // 1000000
            report['compile_phases'] = compile_phase_diagnostics(log, log_start)
            report['compile_counters'] = compile_counter_diagnostics(log, log_start)
        if report['compile_runtime_ms'] >= 35 * 60 * 1000:
            raise ContractError('actual compilation exceeds the original cold-build ceiling')
        run(['build-private/atlas', 'verify-production', '-workspace', ROOT,
             '-atlas', atlas, '-receipt', receipt])
        run(['build-private/atlas', 'corpus', '-atlas', atlas, '-out', corpus])
        measurement = ROOT / 'reports/production-lookup-integration.json'
        run(['go', 'run', './tools/hosted/lookupbench', '-atlas', atlas, '-corpus', corpus,
             '-report', measurement])
        report['lookup_p95_ns'] = verify_lookup_measurement(json.loads(read_private(measurement, 8 << 20)))
        report['passed'] = True
    finally:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_bytes(canonical_bytes(report))


if __name__ == '__main__':
    try:
        main()
    except (ContractError, OSError, ValueError):
        print('Actual-data integration check failed; source details remain private', file=sys.stderr)
        raise SystemExit(1)
