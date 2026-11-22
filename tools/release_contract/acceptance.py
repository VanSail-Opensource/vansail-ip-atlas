"""Derive production gates from raw bound measurements, never policy booleans."""
from __future__ import annotations

import math
import re
import hashlib
from pathlib import Path

from .contracts import ContractError, HASH, NATIVE_LOOKUP_P95_LIMIT_NS

WIDTHS = (320, 390, 1280, 1440)
THEMES = ("light", "dark")
BUILD_SCENARIOS = ("cold_full", "warm_changed", "warm_unchanged", "clock_advance", "withdrawal")
CORPUS_STRATA = ("ipv4_exact", "ipv4_lpm", "ipv6_exact", "ipv6_lpm", "moas", "sparse_asn", "dense_asn", "inherited", "unknown")
GRAPH_FIXTURE_SHA256 = hashlib.sha256((Path(__file__).resolve().parents[2] / "fixtures/bin/synthetic-graph24-via3.json").read_bytes()).hexdigest()


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


def corpus_availability(value: object) -> bool:
    if type(value) is not list or len(value) != len(CORPUS_STRATA):
        return False
    observed = []
    for stratum, row in zip(CORPUS_STRATA, value):
        if (type(row) is not dict or set(row) != {"stratum", "status", "sampled_queries"}
                or row["stratum"] != stratum or type(row["sampled_queries"]) is not int
                or not 0 <= row["sampled_queries"] <= 1200
                or row["status"] != ("observed" if row["sampled_queries"] else "absent")):
            return False
        if row["sampled_queries"]:
            observed.append(stratum)
    return "unknown" in observed and any(s != "unknown" for s in observed)


def population_groups(samples: object) -> dict:
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
    return groups


def valid_ipv4_coverage(coverage) -> bool:
    return coverage is None or (type(coverage) is dict
        and set(coverage) == {"covered_addresses", "network_objects", "router_intervals"}
        and all(type(count) is int for count in coverage.values())
        and coverage["covered_addresses"] == 2**32
        and 1 <= coverage["network_objects"] < 18500
        and coverage["network_objects"] <= coverage["router_intervals"] <= 2**32)


def browser_gates(report: dict) -> dict[str, str]:
    if (report.get("scope") != "hosted-production-browser-v3" or report.get("mode") != "production"
            or report.get("release_scope") != "release-scope-v6" or report.get("errors") != []):
        raise ContractError("production browser evidence has wrong scope or errors")
    if (not HASH.fullmatch(str(report.get("release_id", "")))
            or report.get("corpus_release_id") != report["release_id"]
            or not HASH.fullmatch(str(report.get("corpus_sha256", "")))
            or not corpus_availability(report.get("corpus_availability"))):
        raise ContractError("production corpus availability is not bound to the candidate")
    features = report.get("corpus_features", {})
    if type(features) is not dict or set(features) != {"map", "graph"} or any(type(v) is not bool for v in features.values()):
        raise ContractError("candidate map/graph availability is missing")
    if "corpus_ipv4_network_coverage" not in report:
        raise ContractError("candidate IPv4 population is missing")
    coverage = report["corpus_ipv4_network_coverage"]
    if not valid_ipv4_coverage(coverage):
        raise ContractError("invalid full IPv4 network coverage")
    groups = population_groups(report.get("populations"))
    components = population_groups(report.get("component_populations", []))
    fixture = report.get("graph_component_fixture", {})
    memory = report.get("worst_case_worker_memory", {})
    worker = memory.get("worker_sha256") if type(memory) is dict else None
    fixture_bound = (type(fixture) is dict and fixture.get("scope") == "isolated-synthetic-capacity"
        and fixture.get("fixture_sha256") == GRAPH_FIXTURE_SHA256
        and HASH.fullmatch(str(worker)) is not None and fixture.get("worker_sha256") == worker
        and HASH.fullmatch(str(report.get("candidate_bundle_sha256", ""))) is not None
        and fixture.get("candidate_bundle_sha256") == report["candidate_bundle_sha256"])
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
        component_rows = components[(width, theme)]
        accessibility = complete and len(component_rows) >= 30
        for row in rows:
            events = row.get("interaction_durations_ms", [])
            complete &= (row.get("complete_interaction_script") is True and row.get("event_timing_supported") is True
                         and row.get("completed_routes") == ["overview", "quality", "class-c", "asn", "bgp"]
                         and isinstance(events, list) and len(events) > 0 and all(number(x) for x in events))
            latencies += events if isinstance(events, list) else []
        for row in [*rows, *component_rows]:
            axe = row.get("accessibility", {})
            accessibility &= (type(axe) is dict and axe.get("engine") == "axe-core"
                              and axe.get("violations") == [] and axe.get("incomplete") == [])
        result[prefix + "_lab_INP"] = comparison(latencies, 200) if complete else "unmeasured"
        violation = any(isinstance(row.get("accessibility"), dict) and row["accessibility"].get("violations") for row in [*rows, *component_rows])
        result[prefix + "_accessibility"] = "failed" if violation else "passed" if accessibility else "unmeasured"
        actual_states = len(rows) >= 30
        unknowns = ipv4 = len(rows) >= 30
        for row in rows:
            mapping, graph = row.get("map", {}), row.get("graph", {})
            actual_states &= (type(mapping) is dict and mapping.get("state") == ("observed" if features["map"] else "unavailable")
                and (features["map"] or mapping.get("unknown_state_verified") is True)
                and type(graph) is dict and graph.get("state") == ("observed" if features["graph"] else "unavailable")
                and type(graph.get("visible_nodes")) is int and 0 <= graph["visible_nodes"] <= 24
                and type(graph.get("observed_routes")) is int and graph["observed_routes"] >= 0
                and (graph["observed_routes"] > 0 if features["graph"] else graph["visible_nodes"] == 0 and graph["observed_routes"] == 0 and graph.get("empty_state_verified") is True))
            checks = row.get("unknown_states")
            flags = type(checks) is dict and set(checks) == {"ipv4", "ipv6", "asn"}
            unknowns &= flags and checks["ipv6"] is True and checks["asn"] is True
            ipv4 &= (flags and "ipv4_network_coverage_verified" in row
                and (checks["ipv4"] is True and row["ipv4_network_coverage_verified"] is None if coverage is None
                     else checks["ipv4"] is None and row["ipv4_network_coverage_verified"] is True))
        result[prefix + "_candidate_states"] = "passed" if actual_states else "unmeasured"
        result[prefix + "_ipv6_asn_unknown_states"] = "passed" if unknowns else "unmeasured"
        ipv4_gate = "_ipv4_unknown_state" if coverage is None else "_ipv4_network_coverage"
        result[prefix + ipv4_gate] = "passed" if ipv4 else "unmeasured"
        synthetic_empty = (fixture_bound and len(component_rows) >= 30 and
            all(row.get("worker_sha256") == worker and row.get("ipv4_unknown_state_verified") is True for row in component_rows))
        result[prefix + "_synthetic_ipv4_unknown_state"] = "passed" if synthetic_empty else "unmeasured"
        # Capacity remains the same 24-node workload on the exact emitted code.
        # These isolated synthetic observations never claim real routing coverage.
        graphs = [graph_gate(row.get("graph")) if row.get("worker_sha256") == worker else "unmeasured" for row in component_rows]
        result[prefix + "_graph"] = ("failed" if "failed" in graphs else "passed"
            if fixture_bound and len(component_rows) >= 30 and all(x == "passed" for x in graphs) else "unmeasured")
    # Whole-browser measured peaks are explicitly separate from a 384MiB worker
    # envelope. A sampled JS heap or process RSS cannot be relabelled worker proof.
    memory = report.get("worst_case_worker_memory", {})
    result["worker_memory"] = "unmeasured"
    if (type(memory) is dict and memory.get("accounting") == "isolated-cgroup-v2-memory.peak"
            and memory.get("profile_exercised") == "accepted-worst-case-browser-profile"
            and number(memory.get("peak_bytes")) and memory.get("raw_profile_sha256")
            and memory.get("includes_worker_children") is True and memory.get('errors') == []
            and memory.get('accounting_scope') == 'entire-Chrome-tree-from-process-birth'
            and memory.get('memory_events',{}).get('oom_kill') == 0):
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
    replay = row.get('measurement_scope') == 'authenticated-real-input-engineering-benchmark'
    if type(compiled) is not int or compiled not in (0, 1) or not isinstance(records, list) or not (1 if replay else 3) <= len(records) <= 64 or not isinstance(invocations, list):
        return "unmeasured"
    phases = ['benchmark-state'] if replay else ["intake", "state-fingerprints", "compile-production"] + (["prepare-static"] if compiled == 0 else [])
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
    if (report.get("scope") not in ("hosted-production-build-v1", "hosted-production-build-v2") or report.get("mode") != "production"
            or report.get("errors") != []):
        raise ContractError("production build evidence has wrong scope or errors")
    envelope = report.get('execution_envelope', {})
    result = {'standard_runner':'passed' if envelope.get('scope')=='github-hosted-cgroup-v2'
        and envelope.get('cpu_quota_us')==200000 and envelope.get('cpu_period_us')==100000
        and envelope.get('memory_max_bytes')==8*1024**3 and envelope.get('swap_max_bytes')==0
        and envelope.get('workspace_limit_bytes')==14*1024**3 else 'unmeasured'}
    if report['scope'] == 'hosted-production-build-v2':
        # Every independently measured case needs its finalized outer cgroup
        # report; one good runner profile cannot cover the other fourteen jobs.
        from tools.hosted.production_benchmarks import validate_budget
        envelopes = report.get('execution_envelopes')
        expected = {(name, sample) for name in BUILD_SCENARIOS for sample in (1, 2, 3)}
        observed = set()
        valid = type(envelopes) is list and len(envelopes) == 15
        if valid:
            for row in envelopes:
                if (type(row) is not dict or set(row) != {'scenario', 'sample', 'budget_report'}
                        or type(row['sample']) is not int or type(row['scenario']) is not str
                        or (row['scenario'], row['sample']) not in expected
                        or (row['scenario'], row['sample']) in observed):
                    valid = False
                    break
                observed.add((row['scenario'], row['sample']))
                try:
                    validate_budget(row['budget_report'])
                except ContractError:
                    valid = False
                    break
        result['standard_runner'] = 'passed' if valid and observed == expected else 'unmeasured'
    scenarios = report.get("scenarios", [])
    if report['scope'] == 'hosted-production-build-v2' and (type(scenarios) is not list or len(scenarios) != 15):
        raise ContractError('exactly fifteen production benchmark cases required')
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
            replay = row.get('measurement_scope') == 'authenticated-real-input-engineering-benchmark'
            if row.get("after_state_sha256" if name == "cold_full" and not replay else "before_state_sha256") != state_hash:
                semantic = False
            if name == "cold_full":
                semantic &= before == 0 and after > 0 and row.get("compile_exit_code") == 0 and (replay or row.get("release_id") == report.get("release_id")) and report.get("release_id") is not None
            elif name == "warm_unchanged":
                semantic &= before > 0 and before == after and transition["changed_records"] == 0 and row.get("compile_exit_code") == 0 and (replay or row.get("release_id") == report.get("release_id")) and report.get("release_id") is not None
            elif name == "warm_changed":
                semantic &= before > 0 and before == after and transition["changed_records"] == max(1,(before+99)//100) and row.get("compile_exit_code") == 0
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
        result["go_lookup_p95"] = comparison(lookup["samples_ns"], NATIVE_LOOKUP_P95_LIMIT_NS, minimum=100_000)
    return result


def require_all(gates: dict[str, str]) -> None:
    if not gates or any(value != "passed" for value in gates.values()):
        failed = sorted(key for key, value in gates.items() if value != "passed")
        raise ContractError("mandatory production gates incomplete: " + ", ".join(failed))
