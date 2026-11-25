"""Measure pinned PRIVATE production scenarios; absent transitions remain blocking.

The plan supplies fifteen isolated workspaces, never shell commands. Each must
contain reviewed pinned inputs and the exact checkout. No input or fingerprint is
uploaded. All children, normalized storage, generated output and tools count in
the runner's physical disk/RSS accounting. This script never activates a source.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime
import hashlib
import heapq
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools.release_contract.acceptance import BUILD_SCENARIOS, build_gates, require_all
from tools.release_contract.contracts import ContractError, canonical_bytes, parse_canonical, sha256
from tools.release_contract.production import read_private
from tools.hosted.production_benchmarks import (benchmark_identity, case_report, ENVELOPE,
    json_report, verify_native_lookup)


def private_path(root: Path, value: str) -> Path:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ContractError("invalid private measurement path")
    path = root / value
    resolved = path.resolve(strict=True)
    if not resolved.is_relative_to(root.resolve()) or path.is_symlink():
        raise ContractError("measurement path escaped private bootstrap")
    return resolved


def sorted_records(path: Path, directory: Path):
    """Bounded 32MiB runs; emit private source+semantic keys in external order."""
    runs, chunk, size = [], [], 0
    def flush():
        nonlocal chunk, size
        if not chunk:
            return
        target = directory / f"run-{len(runs)}.txt"
        target.write_bytes(b"".join(sorted(chunk)))
        runs.append(target); chunk, size = [], 0
    with path.open("rb") as source:
        while line := source.readline(8193):
            if len(line) > 8192:
                raise ContractError("state fingerprint line exceeds bound")
            value = json.loads(line)
            if (set(value) != {"source_id", "semantic_sha256"} or not isinstance(value["source_id"], str)
                    or not isinstance(value["semantic_sha256"], str) or len(value["semantic_sha256"]) != 64
                    or any(ch not in "0123456789abcdef" for ch in value["semantic_sha256"])):
                raise ContractError("invalid sealed-state fingerprint row")
            key = canonical_bytes(value) + b"\n"
            chunk.append(key); size += len(key)
            if size >= 32 * 1024 * 1024:
                flush()
    flush()
    streams = [run.open("rb") for run in runs]
    try:
        yield from heapq.merge(*streams)
    finally:
        for stream in streams:
            stream.close()


def transition(before: Path, after: Path, private: Path) -> dict:
    with tempfile.TemporaryDirectory(prefix="fingerprint-sort-", dir=private) as temporary:
        root = Path(temporary); (root / "before").mkdir(); (root / "after").mkdir()
        left, right = sorted_records(before, root / "before"), sorted_records(after, root / "after")
        a, b = next(left, None), next(right, None)
        removed = added = unchanged = 0
        while a is not None or b is not None:
            if b is None or a is not None and a < b:
                removed += 1; a = next(left, None)
            elif a is None or b < a:
                added += 1; b = next(right, None)
            else:
                unchanged += 1; a, b = next(left, None), next(right, None)
    with before.open("rb") as stream:
        before_hash = hashlib.file_digest(stream, "sha256").hexdigest()
    with after.open("rb") as stream:
        after_hash = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"before_records": removed + unchanged, "after_records": added + unchanged,
            "removed_records": removed, "added_records": added, "changed_records": max(removed, added),
            "before_fingerprints_sha256": before_hash, "after_fingerprints_sha256": after_hash}


def disk_bytes(workspace: Path) -> int:
    total = 0
    for relative in (".atlas-private", "build-private", "web/.output"):
        directory = workspace / relative
        if not directory.exists():
            continue
        for root, dirs, files in os.walk(directory, followlinks=False):
            for filename in files:
                path = Path(root) / filename
                if path.is_symlink():
                    raise ContractError("private scratch cannot contain symlinks")
                try:
                    total += path.stat().st_size
                except FileNotFoundError:
                    pass
    return total


def group_rss(group: int) -> int:
    total = 0
    for path in Path("/proc").iterdir():
        if not path.name.isdecimal():
            continue
        try:
            text = (path / "stat").read_text(); tail = text[text.rfind(")") + 2:].split()
            if int(tail[2]) != group:
                continue
            for line in (path / "status").read_text().splitlines():
                if line.startswith("VmRSS:"):
                    total += int(line.split()[1]) * 1024
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            pass
    # The measurement orchestrator also belongs to the compiler working set.
    for line in Path("/proc/self/status").read_text().splitlines():
        if line.startswith("VmHWM:"):
            total += int(line.split()[1]) * 1024
    return total


GO_ALLOCATION_SCOPE = "all-atlas-Go-processes-in-scenario"
GO_PROCESS_SCOPE = "atlas-go-runtime-allocations-v1"
GO_METRIC_KEYS = {"allocated_bytes", "allocation_count", "command", "exit_code", "invocation", "pid", "schema_version", "scope"}


def collect_go_allocations(directory: Path, invocation: str, phase: str, expected: dict[str, int], pid: int, exit_code: int) -> list[dict]:
    """Validate actual Atlas process records, including verifier descendants."""
    entries = list(directory.iterdir())
    if not 1 <= len(entries) <= 64:
        raise ContractError("missing or excessive Go process allocation observations")
    records, identities = [], set()
    for path in entries:
        match = re.fullmatch(r"([0-9a-f]{32})-([1-9][0-9]{0,19})-[0-9a-f]{16}\.json", path.name)
        if match is None:
            raise ContractError("unrecognized Go allocation observation")
        value = parse_canonical(read_private(path, 4096))
        if (type(value) is not dict or set(value) != GO_METRIC_KEYS or value.get("schema_version") != 1
                or type(value["schema_version"]) is not int or value["scope"] != GO_PROCESS_SCOPE
                or value["invocation"] != invocation or match[1] != invocation
                or type(value["pid"]) is not int or not 0 < value["pid"] < 2**32
                or value["pid"] != int(match[2]) or value["pid"] in identities
                or type(value["exit_code"]) is not int or value["exit_code"] not in (0, 1)
                or not isinstance(value["command"], str) or value["command"] not in expected
                or any(type(value[key]) is not int or not 0 < value[key] < 2**64 for key in ("allocation_count", "allocated_bytes"))):
            raise ContractError("Go allocation observation does not bind the invocation")
        identities.add(value["pid"]); records.append(value)
    if Counter(record["command"] for record in records) != Counter(expected):
        raise ContractError("Go allocation observation population incomplete")
    if phase != "prepare-static":
        if len(records) != 1 or records[0]["pid"] != pid or records[0]["exit_code"] != exit_code:
            raise ContractError("Go allocation root process identity or exit differs")
    elif exit_code == 0 and any(record["exit_code"] != 0 for record in records):
        raise ContractError("successful packaging contains failed Go allocation observations")
    return sorted(records, key=lambda record: record["pid"])


def finish_go_metrics(metric: dict) -> None:
    directory = metric.pop("_go_metrics_root", None)
    if directory is not None:
        try:
            Path(directory).rmdir()  # Per-command temporary directories are already empty/removed.
        except OSError:
            raise ContractError("private Go allocation observation cleanup incomplete") from None


def command(args: list[str], workspace: Path, metrics: dict | None = None, *, stdout=None,
            atlas_commands: dict[str, int] | None = None, phase: str | None = None) -> int:
    # Only fixed argv arrays constructed by this module reach subprocess. Private
    # child logs remain in quarantine and are never echoed into public Actions logs.
    environment = {key: value for key, value in os.environ.items() if key not in ("ATLAS_GO_METRICS_DIR", "ATLAS_GO_METRICS_INVOCATION")}
    environment.update(GOMAXPROCS="2", GOMEMLIMIT="5GiB")
    invocation = uuid.uuid4().hex
    temporary = None
    if atlas_commands is not None:
        if metrics is None or "_go_metrics_root" not in metrics or not phase:
            raise ContractError("Go allocation measurement needs an isolated scenario")
        temporary = tempfile.TemporaryDirectory(prefix="invocation-", dir=metrics["_go_metrics_root"])
        environment.update(ATLAS_GO_METRICS_DIR=str(Path(temporary.name).resolve()), ATLAS_GO_METRICS_INVOCATION=invocation)
    try:
        with tempfile.TemporaryFile(dir=workspace / ".atlas-private") as log:
            process = subprocess.Popen(args, cwd=workspace, stdout=stdout or log, stderr=log,
                start_new_session=True, env=environment)
            while process.poll() is None:
                rss, scratch, free = group_rss(process.pid), disk_bytes(workspace), shutil.disk_usage(workspace).free
                if metrics is not None:
                    metrics["runtime_ms"] = ((time.monotonic_ns() - metrics["_started_ns"] + 999999) // 1000000
                        if "_started_ns" in metrics else (time.monotonic() - metrics["_started"]) * 1000)
                    metrics["process_group_peak_rss_bytes"] = max(metrics["process_group_peak_rss_bytes"], rss)
                    metrics["scratch_peak_bytes"] = max(metrics["scratch_peak_bytes"], scratch)
                    metrics["physical_free_low_water_bytes"] = min(metrics["physical_free_low_water_bytes"], free)
                if rss >= 6656 * 1024**2 or scratch >= 10240 * 1024**2 or free < 1024**3:
                    os.killpg(process.pid, signal.SIGKILL); process.wait()
                    raise ContractError("production resource ceiling reached")
                time.sleep(.1)
            if temporary is not None:
                records = collect_go_allocations(Path(temporary.name), invocation, phase, atlas_commands, process.pid, process.returncode)
                metrics["go_processes"].extend(records)
                metrics["go_invocations"].append({"invocation": invocation, "phase": phase, "root_pid": process.pid,
                    "exit_code": process.returncode, "expected_commands": atlas_commands})
                metrics["allocation_count"] += sum(record["allocation_count"] for record in records)
                metrics["allocated_bytes"] += sum(record["allocated_bytes"] for record in records)
                metrics["allocation_process_count"] += len(records)
            return process.returncode
    finally:
        if temporary is not None:
            temporary.cleanup()


def measure(plan: dict, private: Path, atlas_binary: Path, report: dict | None = None) -> dict:
    if sys.platform != "linux":
        raise ContractError("production whole-process-group accounting requires Linux procfs")
    if set(plan) != {"format_version", "mode", "cases"} or plan["format_version"] != 1 or plan["mode"] != "production":
        raise ContractError("invalid production benchmark plan")
    cases = plan["cases"]
    if not isinstance(cases, list) or len(cases) != 15:
        raise ContractError("five production scenarios with three isolated cases each are required")
    if report is None:
        report = {"scope": "hosted-production-build-v1", "mode": "production", "errors": [], "scenarios": []}
    report.update({
        "execution_host": {"logical_cpus": os.cpu_count(), "memory_bytes": os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES"),
            "disk_bytes": shutil.disk_usage(private).total},
        "resource_accounting": {"scope": "entire-child-process-group", "poll_ms": 100,
            "scratch_scope": "private-inputs-normalization-sort-output-and-generation", "blind_spots": "peaks-between-procfs-and-disk-polls; shared-RSS-pages-conservatively-double-counted"}})
    seen, used_workspaces = set(), set()
    for case in cases:
        if (not isinstance(case, dict) or set(case) != {"scenario", "sample", "workspace", "before_clock", "clock", "overlay"}
                or case["scenario"] not in BUILD_SCENARIOS or type(case["sample"]) is not int or case["sample"] not in (1, 2, 3)
                or type(case["clock"]) is not int or type(case["before_clock"]) is not int or not 0 <= case["before_clock"] <= case["clock"]
                or (case["scenario"], case["sample"]) in seen):
            raise ContractError("invalid or duplicate production scenario")
        seen.add((case["scenario"], case["sample"]))
        workspace = private_path(private, case["workspace"])
        if workspace in used_workspaces:
            raise ContractError("each benchmark case requires a distinct pinned workspace")
        used_workspaces.add(workspace)
        if not workspace.is_dir() or not (workspace / ".atlas-private").is_dir():
            raise ContractError("scenario needs an isolated private workspace")
        if workspace.stat().st_dev != private.stat().st_dev or shutil.disk_usage(workspace).total != shutil.disk_usage(private).total:
            raise ContractError("benchmark workspace cannot use an extra physical data volume")
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT).strip()
        if subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=workspace).strip() != head:
            raise ContractError("scenario code revision differs from the trusted checkout")
        dirty = subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], cwd=workspace).decode("utf-8").splitlines()
        if any(line[3:] not in ("configs/sources.yaml", "SOURCES_AUDIT.md") and not line[3:].startswith("fixtures/source-certification/") for line in dirty):
            raise ContractError("scenario changes implementation bytes outside reviewed source inputs")
        name = case["scenario"]
        before, after = workspace / "build-private/measurement-before.ndjson", workspace / "build-private/measurement-after.ndjson"
        before_exists = (workspace / ".atlas-private/state-v1.json").exists()
        if (name == "cold_full") == before_exists:
            raise ContractError("cold requires empty eligible cache; warm scenarios require authentic baseline state")
        if before_exists and command([str(atlas_binary), "state-fingerprints", "-workspace", str(workspace), "-out", str(before), "-clock", str(case["before_clock"])], workspace):
            raise ContractError("baseline sealed state fingerprints failed")
        baseline_state = json.loads(read_private(workspace / ".atlas-private/state-v1.json", 64 * 1024 * 1024)) if before_exists else None
        before_meta = json.loads(read_private(Path(str(before) + ".meta.json"))) if before_exists else None
        overlays = case["overlay"]
        if not isinstance(overlays, list) or (name in ("cold_full", "warm_unchanged", "clock_advance") and overlays):
            raise ContractError("scenario overlay is absent or inappropriate")
        for item in overlays:
            if type(item) is not dict or set(item) != {"from", "to", "sha256"}:
                raise ContractError("invalid reviewed overlay")
            target = item["to"]
            if target not in ("configs/sources.yaml", "SOURCES_AUDIT.md") and not target.startswith("fixtures/source-certification/"):
                raise ContractError("scenario may only change reviewed source policy/fixtures")
            destination = workspace / target
            destination.resolve().relative_to(workspace)
            payload = read_private(private_path(private, item["from"]), 64 * 1024 * 1024)
            if sha256(payload) != item["sha256"] or destination.is_symlink():
                raise ContractError("reviewed overlay hash/path mismatch")
            destination.parent.mkdir(parents=True, exist_ok=True); destination.write_bytes(payload)
        metric = {"scenario": name, "sample": case["sample"], "process_group_peak_rss_bytes": 0,
            "scratch_peak_bytes": 0, "physical_free_low_water_bytes": shutil.disk_usage(workspace).free,
            "allocation_count": 0, "allocated_bytes": 0, "allocation_process_count": 0,
            "allocation_scope": GO_ALLOCATION_SCOPE, "go_processes": [], "go_invocations": [],
            "allocation_exclusions": "Node, Python, Go toolchain and pre-measurement baseline preparation allocations are not included"}
        metric["_go_metrics_root"] = tempfile.mkdtemp(prefix="scenario-go-metrics-", dir=workspace / ".atlas-private")
        started = time.monotonic()
        metric["_started"] = started
        report["scenarios"].append(metric)
        if command([str(atlas_binary), "intake", "-workspace", str(workspace), "-clock", str(case["clock"])], workspace, metric,
                atlas_commands={"intake": 1}, phase="intake"):
            raise ContractError("production scenario intake failed")
        if command([str(atlas_binary), "state-fingerprints", "-workspace", str(workspace), "-out", str(after), "-clock", str(case["clock"])], workspace, metric,
                atlas_commands={"state-fingerprints": 1}, phase="state-fingerprints"):
            raise ContractError("reconciled sealed state fingerprints failed")
        after_meta = json.loads(read_private(Path(str(after) + ".meta.json")))
        metric["input_records"] = after_meta["total_records"]
        after_state = json.loads(read_private(workspace / ".atlas-private/state-v1.json", 64 * 1024 * 1024))
        metric["normalized_input_bytes"] = sum(part["Bytes"] for source in after_state["Sources"] for part in source.get("RecordPartitions", []))
        metric["after_state_sha256"] = after_meta["normalized_state_sha256"]
        with after.open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != after_meta["fingerprint_file_sha256"]:
                raise ContractError("sealed after-state fingerprint binding differs")
        if before_exists:
            metric["before_state_sha256"] = before_meta["normalized_state_sha256"]
            metric["transition"] = transition(before, after, workspace / ".atlas-private")
            if metric["transition"]["before_fingerprints_sha256"] != before_meta["fingerprint_file_sha256"]:
                raise ContractError("sealed before-state fingerprint binding differs")
            before_sources = {entry["source_id"] for entry in before_meta["source_record_counts"]}
            after_sources = {entry["source_id"] for entry in after_meta["source_record_counts"]}
            removed_sources = before_sources - after_sources
            if name == "clock_advance":
                expired = {source["ID"] for source in baseline_state["Sources"]
                    if int(datetime.fromisoformat(source["ExpiresAt"].replace("Z", "+00:00")).timestamp()) <= case["clock"]}
                if not expired or not expired <= removed_sources or case["clock"] <= case["before_clock"]:
                    raise ContractError("clock scenario did not retract authentic expired source influence")
                metric["transition"]["expired_sources_retracted"] = len(expired)
            if name == "withdrawal":
                from tools.atlas_contracts.config import load_yaml
                sources = {entry["id"]: entry for entry in load_yaml(workspace / "configs/sources.yaml")["sources"]}
                withdrawn = {sid for sid in before_sources if sid not in sources or sources[sid]["admission"] == "retired"}
                if not withdrawn or not withdrawn <= removed_sources:
                    raise ContractError("withdrawal scenario did not retract the actual removed sources")
                metric["transition"]["withdrawn_sources_retracted"] = len(withdrawn)
        else:
            metadata = after_meta
            metric["transition"] = {"before_records": 0, "after_records": metadata["total_records"], "added_records": metadata["total_records"], "removed_records": 0, "changed_records": metadata["total_records"]}
        atlas = workspace / "build-private/measurement-atlas"
        receipt = workspace / ".atlas-private/measurement-receipt.json"
        result = command([str(atlas_binary), "compile-production", "-workspace", str(workspace), "-clock", str(case["clock"]), "-out", str(atlas), "-receipt", str(receipt)], workspace, metric,
            atlas_commands={"compile-production": 1}, phase="compile-production")
        metric["compile_exit_code"] = result
        if not result:
            metadata = workspace / "build-private/software-license-metadata.json"
            metadata.parent.mkdir(parents=True, exist_ok=True)
            with metadata.open("wb") as output:
                if command(["npm", "exec", "--yes", "--package", "pnpm@11.28.12", "--", "pnpm", "--dir", "web", "licenses", "list", "--prod", "--json"], workspace, metric, stdout=output):
                    raise ContractError("measurement software notice metadata failed")
            for args in (["python", "tools/release_contract/software_licenses.py"],
                ["npm", "exec", "--yes", "--package", "pnpm@11.28.12", "--", "pnpm", "--dir", "web", "typecheck"],
                ["npm", "exec", "--yes", "--package", "pnpm@11.28.12", "--", "pnpm", "--dir", "web", "generate"],
                ["python", "tools/release_contract/software_licenses.py", "--bundle-audit", "build-private/software-bundle-audit.json", "--require-runtime-review"],
                ["python", "tools/release_contract/prepare_static.py", "--atlas", str(atlas), "--qualification-receipt", str(receipt)]):
                allocation = None
                phase = None
                if args[:2] == ["python", "tools/release_contract/prepare_static.py"]:
                    retained = len(list((atlas / "releases").glob("*/manifest.json")))
                    if not 1 <= retained <= 2:
                        raise ContractError("packaging needs one or two immutable manifests")
                    allocation = {"inspect": 1, "verify-production": 2 * retained}
                    phase = "prepare-static"
                if command(args, workspace, metric, atlas_commands=allocation, phase=phase):
                    raise ContractError("complete production scenario packaging failed")
            metric["release_id"] = json.loads(read_private(receipt))["release_id"]
        elif name not in ("clock_advance", "withdrawal"):
            raise ContractError("full/warm production compilation failed")
        metric["runtime_ms"] = (time.monotonic() - started) * 1000
        del metric["_started"]
        metric["process_group_peak_rss_bytes"] = max(metric["process_group_peak_rss_bytes"], group_rss(-1))
        metric["scratch_peak_bytes"] = max(metric["scratch_peak_bytes"], disk_bytes(workspace))
        finish_go_metrics(metric)
        print(f"Measured production {name} sample {case['sample']}; private inputs retained outside artifacts")
    return report


def measure_replay(atlas_binary: Path, report: dict, *, case: str | None = None, sample: int | None = None) -> None:
    """Replay authenticated real input through the native engineering compiler.

    The mutation output is engineering-only. It cannot qualify a source, become
    a production receipt, or enter the frozen public candidate.
    """
    profile_path = os.environ.get('ATLAS_RUNNER_PROFILE')
    if sys.platform != 'linux' or not profile_path:
        raise ContractError('official hosted cgroup execution profile required')
    report['execution_envelope'] = json.loads(read_private(Path(profile_path)))
    if report['execution_envelope'] != ENVELOPE:
        raise ContractError('official hosted cgroup execution profile differs')
    if (case is None) != (sample is None) or case is not None and (case not in BUILD_SCENARIOS or type(sample) is not int or sample not in (1,2,3)):
        raise ContractError('invalid benchmark case selection')
    report['execution_host'] = {'logical_cpus': os.cpu_count(),
        'memory_bytes': os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES'),
        'disk_bytes': shutil.disk_usage(ROOT).total}
    receipt = json.loads(read_private(ROOT/'.atlas-private/production-receipt.json'))
    clock = receipt['evaluated_at']
    plan = {'version': 2, 'scope': 'authenticated-real-input-engineering-benchmark',
        'clock': clock, 'baseline': receipt['normalized_state_sha256'],
        'scenarios': list(BUILD_SCENARIOS), 'samples': 3, 'changed_records': 'max(1,ceil(N/100))'}
    report['benchmark_plan_sha256'] = sha256(canonical_bytes(plan))
    report['measurement_scope'] = plan['scope']
    report['resource_accounting'] = {'scope':'entire-child-process-group','poll_ms':100,
        'scratch_scope':'all-baseline-inputs-and-isolated-replay-output','blind_spots':'procfs-between-poll-peaks; cgroup peak recorded separately'}
    for name in (BUILD_SCENARIOS if case is None else (case,)):
        for selected_sample in ((1,2,3) if sample is None else (sample,)):
            with tempfile.TemporaryDirectory(prefix='benchmark-', dir=ROOT/'build-private') as directory:
                target = Path(directory)/'workspace'
                argv = [str(atlas_binary),'benchmark-state','-workspace',str(ROOT),'-out',str(target),
                        '-scenario',name,'-clock',str(clock)]
                if name != 'cold_full' and command([*argv,'-prepare'], ROOT):
                    raise ContractError('authenticated engineering baseline preparation failed')
                metric = {'scenario':name,'sample':selected_sample,'measurement_scope':plan['scope'],
                    'process_group_peak_rss_bytes':0,'scratch_peak_bytes':0,
                    'physical_free_low_water_bytes':shutil.disk_usage(ROOT).free,
                    'allocation_count':0,'allocated_bytes':0,'allocation_process_count':0,
                    'allocation_scope':GO_ALLOCATION_SCOPE,'go_processes':[],'go_invocations':[],
                    'allocation_exclusions':'non-Go orchestration and baseline preparation'}
                metric['_go_metrics_root'] = tempfile.mkdtemp(prefix='benchmark-metrics-',dir=ROOT/'.atlas-private')
                metric['_started_ns'] = time.monotonic_ns()
                report['scenarios'].append(metric)
                result_path=Path(directory)/'measurement.json'
                with result_path.open('wb') as output:
                    result=command(argv,ROOT,metric,stdout=output,atlas_commands={'benchmark-state':1},phase='benchmark-state')
                if result:
                    raise ContractError('authenticated engineering benchmark failed')
                observed=json.loads(read_private(result_path))
                if (observed.get('schema_version')!=1 or observed.get('scope')!=plan['scope']
                        or observed.get('scenario')!=name or observed.get('before_state_sha256')!=plan['baseline']):
                    raise ContractError('engineering replay does not bind authentic baseline')
                allowed=('clock','input_records','normalized_input_bytes','before_state_sha256','after_state_sha256',
                         'release_id','compile_exit_code','transition')
                metric.update({key:observed[key] for key in allowed})
                metric['runtime_ms']=(time.monotonic_ns()-metric.pop('_started_ns')+999999)//1000000
                finish_go_metrics(metric)
                print(f'Authenticated engineering {name} sample {selected_sample}/3 measured')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, help="legacy reviewed scenario plan; default derives authenticated replay cases")
    parser.add_argument("--atlas-binary", type=Path, required=True)
    parser.add_argument('--case', choices=BUILD_SCENARIOS)
    parser.add_argument('--sample', type=int, choices=(1,2,3))
    parser.add_argument("--candidate-report", type=Path, default=ROOT / "reports/static-candidate.json")
    parser.add_argument("--lookup-report", type=Path, default=ROOT / "reports/production-lookup.json")
    parser.add_argument("--report", type=Path, default=ROOT / "reports/production-build.json")
    args = parser.parse_args()
    report = {"scope": "hosted-production-build-v1", "mode": "production", "errors": [], "scenarios": []}
    try:
        if (args.case is None) != (args.sample is None) or args.case is not None and args.plan:
            raise ContractError('case and sample require native replay')
        if args.case is not None:
            candidate = json_report(read_private(args.candidate_report))
            receipt = json_report(read_private(ROOT/'.atlas-private/production-receipt.json'))
            context = json_report(read_private(ROOT/'.atlas-private/workflow-context.json'))
            if context.get('format_version') != 2:
                raise ContractError('authenticated benchmark context required')
            identity = benchmark_identity(candidate, receipt, head_sha=context['head_sha'],
                candidate_run_id=context['candidate_run_id'], candidate_run_attempt=context['candidate_run_attempt'])
            measure_replay(args.atlas_binary.resolve(strict=True), report, case=args.case, sample=args.sample)
            if report['benchmark_plan_sha256'] != identity['benchmark_plan_sha256']:
                raise ContractError('benchmark identity changed')
            report = case_report(identity, report['scenarios'][0], run_id=int(os.environ['GITHUB_RUN_ID']),
                run_attempt=int(os.environ['GITHUB_RUN_ATTEMPT']), execution_host=report['execution_host'])
            return 0
        if args.plan:
            plan_bytes = read_private(args.plan)
            measure(json.loads(plan_bytes), args.plan.parent, args.atlas_binary.resolve(strict=True), report)
            report["benchmark_plan_sha256"] = sha256(plan_bytes)
        else:
            measure_replay(args.atlas_binary.resolve(strict=True), report)
        candidate = json.loads(read_private(args.candidate_report))
        if candidate["mode"] != "production":
            raise ContractError("synthetic candidate cannot bind production resource measurements")
        report.update({key: candidate[key] for key in ("release_id", "candidate_bundle_sha256", "qualification_receipt_sha256")})
        report["normalized_state_sha256"] = candidate["normalized_state_sha256"]
        report["go_lookup"] = json.loads(read_private(args.lookup_report, 16 * 1024 * 1024))
        if report["go_lookup"].get("release_id") != report["release_id"]:
            raise ContractError("Go lookup report refers to another release")
        verify_native_lookup(candidate, report['go_lookup'])
        gates = build_gates(report); report["derived_gates"] = gates; require_all(gates)
        return 0
    except (ContractError, OSError, ValueError, KeyError, TypeError) as error:
        report["errors"].append('production-benchmark-failed'); print('FAIL: production build measurements')
        return 1
    finally:
        for row in report["scenarios"]:
            finish_go_metrics(row)
            if "_started" in row:
                row["runtime_ms"] = (time.monotonic() - row.pop("_started")) * 1000
                row["status"] = "incomplete"
            if '_started_ns' in row:
                row['runtime_ms'] = (time.monotonic_ns()-row.pop('_started_ns')+999999)//1000000
                row['status'] = 'incomplete'
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, separators=(",", ":")) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
