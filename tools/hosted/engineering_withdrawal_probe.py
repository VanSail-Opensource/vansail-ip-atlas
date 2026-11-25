"""Measure a single same-clock withdrawal on an isolated 22-source hosted intake."""
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools.hosted.production_benchmarks import (
    LIMIT_CONTRACT, MEASUREMENT_SCOPE, TRANSITION_KEYS, digest, integer, json_report, keys,
)
from tools.hosted.production_workflow import compile_counter_diagnostics, compile_phase_diagnostics, intake_clock
from tools.release_contract.contracts import ContractError, canonical_bytes
from tools.release_contract.production import read_private


def withdrawal_metrics(data, clock, baseline):
    actual = json_report(data, 64 << 10)
    if (type(actual) is not dict or actual.get("scope") != MEASUREMENT_SCOPE or actual.get("scenario") != "withdrawal"
            or integer(actual.get("schema_version")) != 1 or integer(actual.get("compile_exit_code")) != 0
            or integer(actual.get("clock")) != clock):
        raise ContractError("withdrawal did not use the authenticated intake clock")
    transition = keys(actual.get("transition"), TRANSITION_KEYS)
    for count in transition.values():
        integer(count)
    before = integer(actual.get("input_records"), 1)
    hashes = {name: digest(actual.get(name)) for name in ("before_state_sha256", "after_state_sha256", "release_id")}
    removed = transition["removed_records"]
    if (hashes["before_state_sha256"] != baseline or hashes["after_state_sha256"] == baseline
            or transition["before_records"] != before or removed <= 0
            or transition["after_records"] != before - removed or transition["withdrawn_sources_retracted"] <= 0
            or transition["expired_sources_retracted"] or transition["added_records"] or transition["changed_records"]):
        raise ContractError("withdrawal did not remove original records from the authenticated baseline")
    return {"clock": clock, "input_records": before, "transition": transition, **hashes}


def main():
    clock = intake_clock()
    intake = json_report(read_private(ROOT / "reports/source-intake.json", 64 << 10), 64 << 10)
    if (type(intake) is not dict or intake.get("scope") != "actual-source-intake-not-production-acceptance"
            or intake.get("all_active_current") is not True or intake.get("production_eligible") is not False
            or intake.get("blocked_reason_counts") != {} or intake.get("active_sources") != 22
            or intake.get("current_sources") != 22 or intake.get("evaluated_at") != clock):
        raise ContractError("withdrawal requires the current 22-source intake")
    baseline = digest(intake.get("normalized_state_sha256"))
    report = {"scope": "engineering-preflight", "scenario": "withdrawal", "source_count": 22,
              "intake_clock": clock, "normalized_state_sha256": baseline, "measurements": {}}
    report_path = ROOT / "reports/engineering-withdrawal-preflight.json"
    workspace = ROOT / "build-private/benchmark-preflight"
    command = [str(ROOT / "build-private/atlas"), "benchmark-state", "-workspace", str(ROOT),
               "-out", str(workspace), "-scenario", "withdrawal", "-clock", str(clock)]
    for phase, flags in (("prepare", ["-prepare"]), ("withdrawal", [])):
        started = time.monotonic_ns()
        log = ROOT / ".atlas-private" / f"preflight-{phase}.log"
        with log.open("wb") as private:
            result = subprocess.run([*command, *flags], cwd=ROOT, stdout=subprocess.PIPE,
                                    stderr=private, timeout=90 * 60, check=False)
        metric = {"elapsed_ms": (time.monotonic_ns() - started + 999999) // 1000000,
                  "exit_code": result.returncode, "phases": compile_phase_diagnostics(log, 0),
                  "counters": compile_counter_diagnostics(log, 0)}
        report["measurements"][phase] = metric
        report_path.write_bytes(canonical_bytes(report))
        if result.returncode:
            raise ContractError("engineering replay failed")
        if phase == "withdrawal":
            metric.update(withdrawal_metrics(result.stdout, clock, baseline))
            metric["inside_480000_ms"] = metric["elapsed_ms"] < LIMIT_CONTRACT["runtime_ms"]["withdrawal"]
            report_path.write_bytes(canonical_bytes(report))
        print(f"Engineering {phase} completed in {metric['elapsed_ms']} ms", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (ContractError, OSError, ValueError, subprocess.TimeoutExpired):
        raise SystemExit("Hosted engineering withdrawal failed; source details remain private") from None
