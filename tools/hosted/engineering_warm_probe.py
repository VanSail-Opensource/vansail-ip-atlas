"""One isolated transition on the final 23-source PR candidate, for engineering diagnosis."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import runpy
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools.hosted.production_benchmarks import ENVELOPE, LIMIT_CONTRACT, MEASUREMENT_SCOPE, TRANSITION_KEYS, digest, integer, json_report, keys
from tools.hosted.production_workflow import compile_counter_diagnostics, compile_phase_diagnostics, intake_clock
from tools.release_contract.contracts import ContractError, canonical_bytes
from tools.release_contract.production import read_private

BASE = "f0cff9f0616222c839adbbd7bd174f9da06e7098"
PHASES = ("prepare", "measure")
SCENARIOS = ("withdrawal", "clock_advance")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def checked_native(data, clock, baseline, scenario):
    native = keys(json_report(data, 64 << 10), {"schema_version", "scope", "scenario", "clock", "input_records",
        "normalized_input_bytes", "before_state_sha256", "after_state_sha256", "release_id", "compile_exit_code", "transition"})
    current_clock = integer(native["clock"], clock)
    if (integer(native["schema_version"]) != 1 or native["scope"] != MEASUREMENT_SCOPE
            or native["scenario"] != scenario or integer(native["compile_exit_code"]) != 0
            or (current_clock > clock) != (scenario == "clock_advance")):
        raise ContractError("unexpected engineering transition")
    for name in ("before_state_sha256", "after_state_sha256", "release_id"):
        digest(native[name])
    transition = keys(native["transition"], TRANSITION_KEYS)
    for value in transition.values():
        integer(value)
    before = integer(native["input_records"], 1)
    integer(native["normalized_input_bytes"], 1)
    if (native["before_state_sha256"] != baseline or native["after_state_sha256"] == baseline
            or before != transition["before_records"] or transition["removed_records"] <= 0
            or transition["after_records"] != before - transition["removed_records"]
            or transition["added_records"] or transition["changed_records"]
            or (transition["expired_sources_retracted"] > 0) != (scenario == "clock_advance")
            or (transition["withdrawn_sources_retracted"] > 0) != (scenario == "withdrawal")):
        raise ContractError("original authenticated rows were not retracted")
    return native


def run_case(scenario, phase):
    clock = intake_clock()
    intake_bytes = read_private(ROOT / "reports/source-intake.json", 64 << 10)
    intake = json_report(intake_bytes, 64 << 10)
    profile_bytes = read_private(Path(os.environ["ATLAS_RUNNER_PROFILE"]), 16 << 10)
    revision = os.environ["GITHUB_SHA"]
    if (json_report(profile_bytes, 16 << 10) != ENVELOPE or not re.fullmatch("[0-9a-f]{40}", revision)
            or intake.get("scope") != "actual-source-intake-not-production-acceptance"
            or intake.get("all_active_current") is not True or intake.get("production_eligible") is not False
            or intake.get("blocked_reason_counts") != {} or intake.get("active_sources") != 23
            or intake.get("current_sources") != 23 or intake.get("evaluated_at") != clock):
        raise ContractError("complete authenticated intake and standard envelope required")
    baseline = digest(intake["normalized_state_sha256"])
    binary = ROOT / "build-private/atlas"
    with binary.open("rb") as source:
        binary_hash = hashlib.file_digest(source, "sha256").hexdigest()
    out = ROOT / "build-private" / ("p23-benchmark-" + scenario)
    args = [str(binary), "benchmark-state", "-workspace", str(ROOT), "-out", str(out),
            "-scenario", scenario, "-clock", str(clock)]
    if phase == "prepare":
        args.append("-prepare")
    prepare_report = ROOT / "reports" / (scenario + "-prepare-preflight.json")
    report_path = ROOT / "reports" / (scenario + "-" + phase + "-preflight.json")
    report = {"scope": "engineering-preflight", "scenario": scenario, "phase": phase, "intake_clock": clock,
              "source_count": 23, "base_head_sha": BASE, "diagnostic_head_sha": revision,
              "run_id": integer(int(os.environ["GITHUB_RUN_ID"]), 1),
              "run_attempt": integer(int(os.environ["GITHUB_RUN_ATTEMPT"]), 1),
              "intake_sha256": sha(intake_bytes), "normalized_state_sha256": baseline,
              "source_catalog_sha256": digest(intake["source_catalog_sha256"]), "binary_sha256": binary_hash,
              "execution_envelope_sha256": sha(profile_bytes)}
    if phase == "measure":
        prepare_bytes = read_private(prepare_report, 128 << 10)
        prepared = json_report(prepare_bytes, 128 << 10)
        if (any(prepared.get(key) != value for key, value in report.items() if key != "phase")
                or prepared.get("phase") != "prepare" or prepared.get("exit_code") != 0):
            raise ContractError("isolated preparation provenance differs")
        report["prepare_report_sha256"] = sha(prepare_bytes)
    log = ROOT / ".atlas-private" / f"p23-{scenario}-{phase}.log"
    alloc = runpy.run_path(str(ROOT / "tools/hosted/production-build.py"))["collect_go_allocations"]
    invocation = uuid.uuid4().hex
    with tempfile.TemporaryDirectory(dir=ROOT / ".atlas-private") as directory, log.open("wb") as private:
        environment = dict(os.environ, ATLAS_GO_METRICS_DIR=directory, ATLAS_GO_METRICS_INVOCATION=invocation)
        started = time.monotonic_ns()
        process = subprocess.Popen(args, env=environment, cwd=ROOT, stdout=subprocess.PIPE, stderr=private)
        try:
            data, _ = process.communicate(timeout=90 * 60)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            raise
        elapsed = (time.monotonic_ns() - started + 999999) // 1000000
        usage = resource.getrusage(resource.RUSAGE_CHILDREN)
        report.update(elapsed_ms=elapsed, exit_code=process.returncode,
                      child_user_cpu_us=round(usage.ru_utime * 1e6), child_system_cpu_us=round(usage.ru_stime * 1e6),
                      child_peak_rss_bytes=usage.ru_maxrss * 1024,
                      phases=compile_phase_diagnostics(log, 0), counters=compile_counter_diagnostics(log, 0))
        report_path.write_bytes(canonical_bytes(report))
        if process.returncode:
            raise ContractError("native benchmark failed")
        records = alloc(Path(directory), invocation, "benchmark-state", {"benchmark-state": 1}, process.pid, process.returncode)
        report.update(allocation_count=records[0]["allocation_count"], allocated_bytes=records[0]["allocated_bytes"])
    if phase == "measure":
        native = checked_native(data, clock, baseline, scenario)
        before = read_private(ROOT / ".atlas-private/state-v1.json", 64 << 20)
        after = read_private(out / "benchmark-state.json", 64 << 20)
        if sha(before) != native["before_state_sha256"] or sha(after) != native["after_state_sha256"]:
            raise ContractError("original or transformed state byte digest differs")
        def populations(raw):
            sources = json.loads(raw)["Sources"]
            return {row["ID"]: sum(integer(p["Records"], 1) for p in row["RecordPartitions"]) for row in sources}
        old, new = populations(before), populations(after)
        if (len(old) != 23 or not new.keys() < old.keys() or any(old[key] != value for key, value in new.items())
                or sum(old.values()) != native["transition"]["before_records"]
                or sum(new.values()) != native["transition"]["after_records"]
                or sum(old[key] for key in old.keys() - new.keys()) != native["transition"]["removed_records"]):
            raise ContractError("original partition counts differ from the native transition")
        report.update(native=native, native_report_sha256=sha(data),
                      inside_480000_ms=elapsed < LIMIT_CONTRACT["runtime_ms"][scenario])
    report_path.write_bytes(canonical_bytes(report))
    if phase == "measure":
        # The two scenarios have separate baseline copies. Retire only this completed
        # benchmark's generated directory before preparing the next independent copy.
        shutil.rmtree(out)
    print(f"Engineering {scenario} {phase} completed in {elapsed} ms", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=SCENARIOS)
    parser.add_argument("phase", choices=PHASES)
    args = parser.parse_args()
    try:
        run_case(args.scenario, args.phase)
    except (ContractError, OSError, ValueError, KeyError, subprocess.TimeoutExpired):
        raise SystemExit("Hosted engineering warm check failed; details remain private") from None
