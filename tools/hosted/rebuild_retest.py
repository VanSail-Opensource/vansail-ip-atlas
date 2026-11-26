"""Measure one actual transition without issuing a production receipt."""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
sys.path.insert(0, str(ROOT))
from tools.hosted.production_benchmarks import ENVELOPE, LIMIT_CONTRACT, MEASUREMENT_SCOPE, TRANSITION_KEYS, integer, json_report, keys
from tools.hosted.production_workflow import intake_clock
from tools.release_contract.contracts import ContractError, canonical_bytes
from tools.release_contract.production import read_private

case = argparse.ArgumentParser(description=__doc__)
case.add_argument("scenario", choices=("warm_changed", "clock_advance", "withdrawal"))
scenario = case.parse_args().scenario
build = runpy.run_path(str(ROOT / "tools/hosted/production-build.py"))
report = {"scope": "authenticated-real-rebuild-diagnostic", "scenario": scenario, "error_stage": None}
stage = "environment"


def profile_summary(profile):
    """Retain bounded compiled function timings, never raw profiles or paths."""
    names = ("vansail-ip-atlas/internal/", "runtime.", "encoding/json", "net/netip.",
             "crypto/internal/", "github.com/klauspost/compress/zstd.", "math.", "os.", "syscall.")
    result = {}
    for key, flags in (("self", []), ("inclusive", ["-cum"])):
        top = subprocess.run(["go", "tool", "pprof", "-top", "-nodecount=55", *flags,
                              str(ROOT / "build-private/atlas"), str(profile)],
                             cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             timeout=25, check=False, text=True)
        if top.returncode != 0 or len(top.stdout) > 64 << 10:
            raise ContractError("source-free profile report unavailable")
        result[key] = []
        for line in top.stdout.splitlines():
            fields = line.split()
            if len(fields) < 6 or not all(re.fullmatch(r"[0-9.]+(s|ms|us|ns|%)?", field) for field in fields[:5]):
                continue
            symbol = fields[5]
            if len(symbol) <= 180 and symbol.startswith(names) and re.fullmatch(r"[\w./*()[\],·-]+", symbol):
                result[key].append({"function": symbol, "self": fields[0], "inclusive": fields[3]})
    return result


def partition_population(data):
    rows = json.loads(data)["Sources"]
    counts = {row["ID"]: sum(integer(p["Records"], 1) for p in row["RecordPartitions"]) for row in rows}
    if len(counts) != len(rows):
        raise ContractError("duplicate source in engineering state")
    return counts


try:
    head = os.environ["ATLAS_REPLAY_COMPILER"]
    if subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip() != head:
        raise ContractError("compiler revision differs")
    profile = json_report(read_private(Path(os.environ["ATLAS_RUNNER_PROFILE"]), 16 << 10))
    if profile != ENVELOPE:
        raise ContractError("standard hosted runner envelope required")
    clock = intake_clock()
    intake = json_report(read_private(ROOT / "reports/source-intake.json", 64 << 10))
    if (intake["all_active_current"] is not True or intake["current_sources"] != 23
            or intake["active_sources"] != 23 or intake["evaluated_at"] != clock):
        raise ContractError("complete authenticated intake required")
    report.update(compiler_head=head, intake_sources=23, evaluated_at=clock, envelope=profile)
    with tempfile.TemporaryDirectory(prefix="benchmark-retest-", dir=ROOT / "build-private") as temp:
        root = Path(temp)
        out = root / "workspace"
        argv = [str(ROOT / "build-private/atlas"), "benchmark-state", "-workspace", str(ROOT),
                "-out", str(out), "-scenario", scenario, "-clock", str(clock)]
        stage = "prepare"
        start = time.monotonic_ns()
        if build["command"]([*argv, "-prepare"], ROOT):
            raise ContractError("authenticated baseline preparation failed")
        report["prepare_ms"] = (time.monotonic_ns() - start + 999999) // 1000000
        print("Authenticated engineering baseline prepared", flush=True)
        stage = "measure"
        metric = dict(process_group_peak_rss_bytes=0, scratch_peak_bytes=0, allocation_count=0,
                      allocated_bytes=0, allocation_process_count=0, go_processes=[], go_invocations=[],
                      physical_free_low_water_bytes=shutil.disk_usage(ROOT).free)
        result = root / "measurement.json"
        profile = root / "private-expiry.pprof"
        with tempfile.TemporaryDirectory(prefix="retest-metrics-", dir=ROOT / ".atlas-private") as metrics:
            metric["_go_metrics_root"] = metrics
            metric["_started_ns"] = start = time.monotonic_ns()
            os.environ["ATLAS_DIAGNOSTIC_CPU_PROFILE"] = str(profile)
            try:
                with result.open("wb") as output:
                    status = build["command"](argv, ROOT, metric, stdout=output, atlas_commands={"benchmark-state": 1}, phase="benchmark-state")
            finally:
                del os.environ["ATLAS_DIAGNOSTIC_CPU_PROFILE"]
            metric["runtime_ms"] = (time.monotonic_ns() - start + 999999) // 1000000
            del metric["_go_metrics_root"], metric["_started_ns"]
        report["measurement"] = metric
        if status:
            raise ContractError("native engineering measurement failed")
        stage = "profile"
        report["instrumented_measurement"] = True
        report["cpu_functions"] = profile_summary(profile)
        stage = "transition"
        native = json_report(read_private(result, 64 << 10))
        if (native["schema_version"] != 1 or native["scope"] != MEASUREMENT_SCOPE
                or native["scenario"] != scenario or native["compile_exit_code"] != 0
                or native["before_state_sha256"] != intake["normalized_state_sha256"]):
            raise ContractError("native observation does not bind authenticated input")
        original = read_private(ROOT / ".atlas-private/state-v1.json", 64 << 20)
        updated = read_private(out / "benchmark-state.json", 64 << 20)
        if (native["before_state_sha256"] != sha256(original).hexdigest()
                or native["after_state_sha256"] != sha256(updated).hexdigest() or original == updated):
            raise ContractError("engineering state identity differs")
        before, after = partition_population(original), partition_population(updated)
        total = sum(before.values())
        transition = keys(native["transition"], TRANSITION_KEYS)
        expected = dict(before_records=total, after_records=sum(after.values()), added_records=0,
                        removed_records=0, changed_records=0, expired_sources_retracted=0,
                        withdrawn_sources_retracted=0)
        if scenario == "warm_changed":
            if after != before or native["clock"] != clock:
                raise ContractError("changed-case population differs")
            changed = (total + 99) // 100
            expected.update(added_records=changed, removed_records=changed, changed_records=changed)
        else:
            removed = set(before) - set(after)
            if not removed or not after.keys() < before.keys() or any(before[k] != v for k, v in after.items()):
                raise ContractError("retained source count differs")
            expected["removed_records"] = sum(before[k] for k in removed)
            if scenario == "clock_advance":
                if native["clock"] <= clock:
                    raise ContractError("expiry clock did not advance")
                expected["expired_sources_retracted"] = transition["expired_sources_retracted"]
                integer(expected["expired_sources_retracted"], 1, len(removed))
            else:
                if native["clock"] != clock:
                    raise ContractError("withdrawal clock changed")
                expected["withdrawn_sources_retracted"] = 1
        if total != native["input_records"] or transition != expected:
            raise ContractError("native transition differs from authenticated rows")
        report["transition"] = transition
        stage = "runtime"
        limit = LIMIT_CONTRACT["runtime_ms"][scenario]
        report["limit_ms"] = limit
        if metric["runtime_ms"] >= limit:
            raise ContractError("existing runtime ceiling exceeded")
except (ContractError, OSError, ValueError, KeyError, subprocess.SubprocessError):
    report["error_stage"] = stage
finally:
    (ROOT / "reports/rebuild-retest.json").write_bytes(canonical_bytes(report))
if report["error_stage"] is not None:
    raise SystemExit("Actual rebuild diagnostic failed: " + report["error_stage"])
print("Actual rebuild diagnostic passed")
