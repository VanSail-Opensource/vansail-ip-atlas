"""Measure one private engineering transition from the exact hosted intake."""
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools.hosted.production_workflow import compile_counter_diagnostics, compile_phase_diagnostics, intake_clock


def main():
    report = {"scope": "engineering-preflight", "scenario": "clock_advance", "measurements": {}}
    report_path = ROOT / "reports/engineering-warm-preflight.json"
    workspace = ROOT / "build-private/benchmark-preflight"
    command = [str(ROOT / "build-private/atlas"), "benchmark-state", "-workspace", str(ROOT),
               "-out", str(workspace), "-scenario", report["scenario"], "-clock", str(intake_clock())]
    for phase, flags in (("prepare", ["-prepare"]), ("clock_advance", [])):
        started = time.monotonic_ns()
        log = ROOT / ".atlas-private" / f"preflight-{phase}.log"
        with log.open("wb") as private:
            result = subprocess.run([*command, *flags], cwd=ROOT, stdout=subprocess.PIPE,
                                    stderr=private, timeout=90 * 60, check=False)
        metric = {"elapsed_ms": (time.monotonic_ns() - started + 999999) // 1000000,
                  "exit_code": result.returncode, "phases": compile_phase_diagnostics(log, 0),
                  "counters": compile_counter_diagnostics(log, 0)}
        report["measurements"][phase] = metric
        report_path.write_text(json.dumps(report) + "\n")
        if result.returncode:
            raise SystemExit("Engineering replay failed during " + phase)
        if phase == "clock_advance":
            actual = json.loads(result.stdout)
            if (actual["scope"] != "authenticated-real-input-engineering-benchmark"
                    or actual["scenario"] != "clock_advance" or actual["compile_exit_code"] != 0
                    or actual["transition"]["removed_records"] <= 0):
                raise SystemExit("Engineering replay did not measure a real expiry")
            metric["input_records"] = actual["input_records"]
            metric["removed_records"] = actual["transition"]["removed_records"]
            metric["inside_480000_ms"] = metric["elapsed_ms"] < 480000
            report_path.write_text(json.dumps(report) + "\n")
        print(f"Engineering {phase} completed in {metric['elapsed_ms']} ms", flush=True)


if __name__ == "__main__":
    main()
