"""Compile actual admitted data in integration; never package or deploy a site."""
from __future__ import annotations
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools.hosted.production_workflow import compile_phase_diagnostics, intake_clock, run
from tools.release_contract.contracts import ContractError, canonical_bytes
from tools.release_contract.production import read_private


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
