"""Derive production gates from raw bound measurements, never policy booleans."""
from __future__ import annotations

import math
import re

from .contracts import ContractError, HASH

WIDTHS = (320, 390, 1280, 1440)
THEMES = ("light", "dark")
BUILD_SCENARIOS = ("cold_full", "warm_changed", "warm_unchanged", "clock_advance", "withdrawal")


def number(value: object) -> bool:
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def percentile(values: list, rank: float) -> float | None:
    if not values or any(not number(value) for value in values):
        return None
    return sorted(values)[max(0, math.ceil(len(values) * rank) - 1)]


def comparison(values: list, limit: float, *, minimum: int = 1, maximum=False, inclusive=False) -> str:
    if len(values) < minimum:
        return "unmeasured"
    value = max(values) if maximum and all(number(x) for x in values) else percentile(values, .95)
    if value is None:
        return "unmeasured"
    return "passed" if (value <= limit if inclusive else value < limit) else "failed"


def graph_gate(graph: object) -> str:
    if type(graph) is not dict or graph.get("visible_nodes") != 24:
        return "unmeasured"
    phases = graph.get("active_frames", [])
    for name in ("keyboard-pan", "wheel-zoom", "route-focus"):
        matches = [p for p in phases if isinstance(p, dict) and p.get("action") == name]
        if len(matches) != 1:
            return "unmeasured"
        phase = matches[0]
        frames, populations = phase.get("complete_second_fps", []), phase.get("population_checkpoints", [])
        if (not number(phase.get("duration_ms")) or phase["duration_ms"] < 10_000
                or not number(phase.get("actions")) or phase["actions"] < 1
                or len(frames) < 10 or not all(number(value) for value in frames)
                or len(populations) < 12):
            return "unmeasured"
        # Recompute physical visibility from every raw box rather than trusting counts.
        for sample in populations:
            if not isinstance(sample, dict) or len(sample.get("circles", [])) != 24:
                return "unmeasured"
            bounds = [sample.get("svg_bounds"), sample.get("visible_bounds")]
            for box in [*bounds, *sample["circles"]]:
                if (not isinstance(box, dict) or any(not number(box.get(key)) and not
                    (type(box.get(key)) in (int, float) and math.isfinite(box[key]))
                    for key in ("left", "right", "top", "bottom"))
                        or box["right"] <= box["left"] or box["bottom"] <= box["top"]):
                    return "unmeasured"
            for circle in sample["circles"]:
                if not all(circle["left"] >= b["left"] and circle["right"] <= b["right"]
                        and circle["top"] >= b["top"] and circle["bottom"] <= b["bottom"] for b in bounds):
                    return "failed"
        if min(frames) < 50:
            return "failed"
    return "passed"


def browser_gates(report: dict) -> dict[str, str]:
    if (report.get("scope") != "hosted-production-browser-v1" or report.get("mode") != "production"
            or report.get("errors") != []):
        raise ContractError("production browser evidence has wrong scope or errors")
    samples = report.get("populations")
    if not isinstance(samples, list):
        raise ContractError("production browser evidence has no raw populations")
    groups = {(width, theme): [] for width in WIDTHS for theme in THEMES}
    seen = set()
    for sample in samples:
        if not isinstance(sample, dict):
            raise ContractError("invalid browser population")
        key = (sample.get("width"), sample.get("theme"))
        identity = (*key, sample.get("sample"))
        if (key not in groups or type(sample.get("sample")) is not int or sample["sample"] < 1
                or identity in seen):
            raise ContractError("unknown or duplicate browser population")
        seen.add(identity)
        groups[key].append(sample)
    result = {}
    for (width, theme), rows in groups.items():
        prefix = f"browser_{width}_{theme}"
        result[prefix + "_population"] = "passed" if len(rows) >= 30 else "unmeasured"
        for field, limit, maximum in (("lcp_ms", 2500, False), ("initial_js_gzip_bytes", 200 * 1024, False),
                                      ("interaction_cls", .1, True)):
            result[prefix + "_" + field] = comparison([row.get(field) for row in rows], limit, minimum=30, maximum=maximum)
        # Event Timing interaction IDs are grouped in the browser; raw per-interaction
        # maximum durations are retained. Missing/unsupported observers cannot pass.
        latencies = []
        complete = len(rows) >= 30
        accessibility = complete
        for row in rows:
            events = row.get("interaction_durations_ms", [])
            complete &= (row.get("complete_interaction_script") is True and row.get("event_timing_supported") is True
                         and isinstance(events, list) and len(events) > 0 and all(number(x) for x in events))
            latencies += events if isinstance(events, list) else []
            axe = row.get("accessibility", {})
            accessibility &= (type(axe) is dict and axe.get("engine") == "axe-core"
                              and axe.get("violations") == [] and axe.get("incomplete") == [])
        result[prefix + "_lab_INP"] = comparison(latencies, 200) if complete else "unmeasured"
        violation = any(isinstance(row.get("accessibility"), dict) and row["accessibility"].get("violations") for row in rows)
        result[prefix + "_accessibility"] = "failed" if violation else "passed" if accessibility else "unmeasured"
        graphs = [graph_gate(row.get("graph")) for row in rows]
        result[prefix + "_graph"] = "failed" if "failed" in graphs else "passed" if len(rows) >= 30 and all(x == "passed" for x in graphs) else "unmeasured"
    # Whole-browser measured peaks are explicitly separate from a 384MiB worker
    # envelope. A sampled JS heap or process RSS cannot be relabelled worker proof.
    memory = report.get("worst_case_worker_memory", {})
    result["worker_memory"] = "unmeasured"
    if (type(memory) is dict and memory.get("accounting") == "isolated-cgroup-v2-memory.peak"
            and memory.get("profile_exercised") == "accepted-worst-case-browser-profile"
            and number(memory.get("peak_bytes")) and memory.get("raw_profile_sha256")
            and memory.get("includes_worker_children") is True):
        result["worker_memory"] = comparison([memory["peak_bytes"]], 384 * 1024**2, maximum=True)
    cold = report.get("cold_queries", [])
    result["cold_payload"] = comparison([row.get("atlas_body_bytes") for row in cold if isinstance(row, dict)],
                                         400 * 1024, minimum=100)
    hot = report.get("hot_queries", [])
    for context in range(1, 4):
        rows = [row for row in hot if isinstance(row, dict) and row.get("context") == context]
        if len(rows) != 1 or rows[0].get("warmups", 0) < 100 or rows[0].get("timing") != "actual-worker-indexed-lookups":
            result[f"browser_hot_lookup_{context}"] = "unmeasured"
        else:
            result[f"browser_hot_lookup_{context}"] = comparison(rows[0].get("samples_ms", []), 15, minimum=1000)
    return result


def allocation_gate(row: dict) -> str:
    """Recompute the complete measured Atlas process population and totals."""
    if row.get("allocation_scope") != "all-atlas-Go-processes-in-scenario":
        return "unmeasured"
    records, invocations = row.get("go_processes"), row.get("go_invocations")
    compiled = row.get("compile_exit_code")
    if type(compiled) is not int or compiled not in (0, 1) or not isinstance(records, list) or not 3 <= len(records) <= 64 or not isinstance(invocations, list):
        return "unmeasured"
    phases = ["intake", "state-fingerprints", "compile-production"] + (["prepare-static"] if compiled == 0 else [])
    if len(invocations) != len(phases):
        return "unmeasured"
    process_keys = {"allocated_bytes", "allocation_count", "command", "exit_code", "invocation", "pid", "schema_version", "scope"}
    used, total_count, total_bytes = set(), 0, 0
    for invocation, phase in zip(invocations, phases):
        if (type(invocation) is not dict or set(invocation) != {"invocation", "phase", "root_pid", "exit_code", "expected_commands"}
                or invocation["phase"] != phase or not isinstance(invocation["invocation"], str)
                or re.fullmatch(r"[0-9a-f]{32}", invocation["invocation"]) is None or invocation["invocation"] in used
                or type(invocation["root_pid"]) is not int or not 0 < invocation["root_pid"] < 2**32
                or type(invocation["exit_code"]) is not int or invocation["exit_code"] != (compiled if phase == "compile-production" else 0)
                or type(invocation["expected_commands"]) is not dict):
            return "unmeasured"
        used.add(invocation["invocation"])
        expected = invocation["expected_commands"]
        if phase == "prepare-static":
            if set(expected) != {"inspect", "verify-production"} or type(expected["inspect"]) is not int or expected["inspect"] != 1 or type(expected["verify-production"]) is not int or expected["verify-production"] not in (2, 4):
                return "unmeasured"
        elif expected != {phase: 1} or type(expected.get(phase)) is not int:
            return "unmeasured"
        found, pids = {}, set()
        for record in records:
            if type(record) is not dict or set(record) != process_keys:
                return "unmeasured"
            if record["invocation"] != invocation["invocation"]:
                continue
            if (type(record["schema_version"]) is not int or record["schema_version"] != 1
                    or record["scope"] != "atlas-go-runtime-allocations-v1" or not isinstance(record["command"], str)
                    or record["command"] not in expected or type(record["pid"]) is not int or not 0 < record["pid"] < 2**32 or record["pid"] in pids
                    or type(record["exit_code"]) is not int or record["exit_code"] != invocation["exit_code"]
                    or any(type(record[key]) is not int or not 0 < record[key] < 2**64 for key in ("allocation_count", "allocated_bytes"))):
                return "unmeasured"
            if phase != "prepare-static" and record["pid"] != invocation["root_pid"]:
                return "unmeasured"
            pids.add(record["pid"])
            found[record["command"]] = found.get(record["command"], 0) + 1
            total_count += record["allocation_count"]; total_bytes += record["allocated_bytes"]
        if found != expected:
            return "unmeasured"
    if (any(type(record.get("invocation")) is not str or record["invocation"] not in used for record in records)
            or type(row.get("allocation_count")) is not int or row["allocation_count"] != total_count
            or type(row.get("allocated_bytes")) is not int or row["allocated_bytes"] != total_bytes
            or type(row.get("allocation_process_count")) is not int or row["allocation_process_count"] != len(records)):
        return "unmeasured"
    return "passed"


def build_gates(report: dict) -> dict[str, str]:
    if (report.get("scope") != "hosted-production-build-v1" or report.get("mode") != "production"
            or report.get("errors") != []):
        raise ContractError("production build evidence has wrong scope or errors")
    host = report.get("execution_host", {})
    result = {"standard_runner": "passed" if host.get("logical_cpus") == 2
        and number(host.get("memory_bytes")) and 7 * 1024**3 <= host["memory_bytes"] <= 8 * 1024**3
        and number(host.get("disk_bytes")) and 13 * 1024**3 <= host["disk_bytes"] <= 14 * 1024**3 else "unmeasured"}
    scenarios = report.get("scenarios", [])
    for name in BUILD_SCENARIOS:
        rows = [row for row in scenarios if isinstance(row, dict) and row.get("scenario") == name]
        identities = [row.get("sample") for row in rows]
        semantic = len(rows) == 3 and all(type(value) is int for value in identities) and sorted(identities) == [1, 2, 3]
        for row in rows:
            transition = row.get("transition", {})
            if not isinstance(transition, dict) or not all(type(transition.get(key)) is int and transition[key] >= 0
                    for key in ("before_records", "after_records", "added_records", "removed_records", "changed_records")):
                semantic = False
                continue
            before, after = transition["before_records"], transition["after_records"]
            state_hash = report.get("normalized_state_sha256")
            if not isinstance(state_hash, str) or HASH.fullmatch(state_hash) is None:
                semantic = False
            elif row.get("after_state_sha256" if name == "cold_full" else "before_state_sha256") != state_hash:
                semantic = False
            if name == "cold_full":
                semantic &= before == 0 and after > 0 and row.get("compile_exit_code") == 0 and row.get("release_id") == report.get("release_id") and report.get("release_id") is not None
            elif name == "warm_unchanged":
                semantic &= before > 0 and before == after and transition["changed_records"] == 0 and row.get("compile_exit_code") == 0 and row.get("release_id") == report.get("release_id") and report.get("release_id") is not None
            elif name == "warm_changed":
                semantic &= before > 0 and before == after and transition["changed_records"] * 100 == before and row.get("compile_exit_code") == 0
            elif name == "clock_advance":
                semantic &= type(transition.get("expired_sources_retracted")) is int and transition["expired_sources_retracted"] > 0 and transition["removed_records"] > 0
            elif name == "withdrawal":
                semantic &= type(transition.get("withdrawn_sources_retracted")) is int and transition["withdrawn_sources_retracted"] > 0 and transition["removed_records"] > 0
        result[name + "_actual_transition"] = "passed" if semantic else "unmeasured"
        result[name + "_go_allocations"] = "passed" if len(rows) == 3 and all(allocation_gate(row) == "passed" for row in rows) else "unmeasured"
        limit = 35 * 60_000 if name == "cold_full" else 3 * 60_000 if name == "warm_unchanged" else 8 * 60_000
        result[name + "_runtime"] = comparison([row.get("runtime_ms") for row in rows], limit, minimum=3, maximum=True)
        for field, budget in (("process_group_peak_rss_bytes", 6656 * 1024**2), ("scratch_peak_bytes", 10240 * 1024**2)):
            result[name + "_" + field] = comparison([row.get(field) for row in rows], budget, minimum=3, maximum=True)
    lookup = report.get("go_lookup", {})
    result["go_lookup_p95"] = "unmeasured"
    if (lookup.get("corpus_queries") == 10_000 and lookup.get("warmups", 0) >= 1000
            and lookup.get("timing") == "individual-indexed-lookups" and len(lookup.get("samples_ns", [])) >= 100_000):
        result["go_lookup_p95"] = comparison(lookup["samples_ns"], 2000, minimum=100_000)
    return result


def require_all(gates: dict[str, str]) -> None:
    if not gates or any(value != "passed" for value in gates.values()):
        failed = sorted(key for key, value in gates.items() if value != "passed")
        raise ContractError("mandatory production gates incomplete: " + ", ".join(failed))
