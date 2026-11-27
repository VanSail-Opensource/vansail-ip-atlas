"""Bind independently measured browser populations to a single immutable preview."""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import sys
import tempfile

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.hosted.candidate import check_preview_origin
from tools.release_contract.acceptance import GRAPH_FIXTURE_SHA256, THEMES, WIDTHS, browser_gates, number, require_all
from tools.release_contract.contracts import ContractError, HASH, sha256
from tools.release_contract.promotion import json_object

ROOT = Path(__file__).resolve().parents[2]
DIMENSIONS = {f"{w}-{t}": (w, t) for w in WIDTHS for t in THEMES}
SHARDS = (*DIMENSIONS, "queries")
ARRAYS = ("populations", "component_populations", "cold_queries", "hot_queries")
VARIABLE = {*ARRAYS, "worker_memory_samples", "browser_process_tree_rss_peak_bytes", "execution_host"}
PART_NAME = "production-browser-part.json"
# Closed exit-code channel for the existing --part validator. Keep this in
# sync with the report-gate classes in browser-failures.mjs.
GATE_FAILURE_EXIT = {
    "graph": 41, "accessibility": 42, "lcp_ms": 43, "initial_js_gzip_bytes": 44,
    "interaction_cls": 45, "lab_INP": 46, "population": 47, "candidate_states": 48,
    "ipv6_asn_unknown_states": 49, "ipv4_unknown_state": 50, "ipv4_network_coverage": 50,
    "synthetic_ipv4_unknown_state": 51, "worker_memory": 52, "cold_payload": 53,
    "1": 54, "2": 54, "3": 54,  # browser_hot_lookup_ contexts
}


class BrowserGateFailure(ContractError):
    def __init__(self, exit_code):
        super().__init__("mandatory production browser gate incomplete")
        self.exit_code = exit_code


def require(ok, message):
    if not ok:
        raise ContractError(message)


def integer(value):
    return type(value) is int and value > 0


def read_data(path):
    require(path.is_file() and not path.is_symlink(), "missing or indirect browser evidence file")
    return path.read_bytes()


@dataclass(frozen=True)
class Identity:
    head_sha: str
    run_id: str
    run_attempt: str
    fields: dict
    cold_strata: list


def identity(root, env):
    head, run, attempt = (env.get(k, "") for k in ("GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"))
    require(re.fullmatch(r"[0-9a-f]{40}", head) and all(re.fullmatch(r"[1-9][0-9]*", v) for v in (run, attempt)),
            "invalid browser measurement run identity")
    reports = root / "reports"
    candidate = json_object(read_data(reports / "static-candidate.json"))
    deployment = json_object(read_data(reports / "pages-deployment.json"))
    memory = json_object(read_data(reports / "worker-memory.json"))
    raw = read_data(root / env.get("ATLAS_PRODUCTION_CORPUS", ".atlas-private/production-browser-corpus.json"))
    corpus = json_object(raw)
    fields = {k: candidate.get(k) for k in ("release_id", "candidate_bundle_sha256", "qualification_receipt_sha256")}
    require(candidate.get("status") == "passed" and candidate.get("mode") == "production"
            and all(isinstance(v, str) and HASH.fullmatch(v) for v in fields.values()), "invalid frozen browser candidate")
    url = check_preview_origin(deployment["url"])
    require(deployment.get("status") == "verified" and deployment.get("operation") == "preview"
            and deployment.get("environment") == "preview" and deployment.get("head_sha") == head
            and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", str(deployment.get("deployment_id")))
            and url.split("//")[1].split(".")[0] == deployment["deployment_id"][:8]
            and all(deployment.get(k) == fields[k] for k in ("release_id", "candidate_bundle_sha256")),
            "deployment differs from frozen browser candidate")
    require(corpus.get("format_version") == 3 and corpus.get("mode") == "production"
            and corpus.get("release_id") == fields["release_id"] and len(corpus.get("queries", [])) == 10_000,
            "browser corpus differs from frozen candidate")
    require(isinstance(memory.get("worker_sha256"), str) and HASH.fullmatch(memory["worker_sha256"]),
            "missing measured worker identity")
    coverage = corpus["ipv4_network_coverage"]
    fields.update(scope="hosted-production-browser-v3", mode="production", release_scope="release-scope-v6",
                  url=url, head_sha=head, corpus_release_id=corpus["release_id"], corpus_sha256=sha256(raw),
                  graph_component_fixture={"scope": "isolated-synthetic-capacity", "fixture_sha256": GRAPH_FIXTURE_SHA256,
                      "worker_sha256": memory["worker_sha256"], "candidate_bundle_sha256": fields["candidate_bundle_sha256"]},
                  corpus_availability=corpus["availability"], worst_case_worker_memory=memory,
                  corpus_features={"map": corpus["map_query"] is not None, "graph": corpus["graph_query"] is not None},
                  corpus_ipv4_network_coverage=None if coverage is None else
                  {k: coverage[k] for k in ("covered_addresses", "network_objects", "router_intervals")})
    ip_strata = [row["stratum"] for row in corpus["queries"] if not row["q"].startswith("AS")]
    require(len(ip_strata) >= 100, "browser corpus lacks the cold IP population")
    return Identity(head, run, attempt, fields, [ip_strata[i * len(ip_strata) // 100] for i in range(100)])


def indices(rows, field, count):
    require(type(rows) is list and len(rows) == count and
            all(type(row) is dict and integer(row.get(field)) for row in rows)
            and {row[field] for row in rows} == set(range(1, count + 1)), "incomplete or duplicate browser sample indices")


def peak_sample(report):
    samples = report.get("worker_memory_samples")
    require(type(samples) is list and samples, "missing browser process RSS observations")
    peak = None
    for row in samples:
        require(type(row) is dict and type(row.get("supported")) is bool and number(row.get("at_ms"))
                and type(row.get("processes")) is int and type(row.get("rss_bytes")) is int,
                "invalid browser RSS observation")
        if row["supported"]:
            require(row["processes"] > 0 and row["rss_bytes"] > 0, "empty supported browser RSS observation")
            if peak is None or row["rss_bytes"] > peak["rss_bytes"]:
                peak = row
        else:
            require(row["processes"] == row["rss_bytes"] == 0, "unavailable browser RSS carried a measurement")
    require(peak and integer(report.get("browser_process_tree_rss_peak_bytes"))
            and report["browser_process_tree_rss_peak_bytes"] == peak["rss_bytes"], "browser process RSS peak mismatch")
    return peak


def validate_part(packet, shard, expected):
    require(shard in SHARDS and type(packet) is dict and set(packet) ==
            {"schema_version", "shard", "head_sha", "run_id", "run_attempt", "report"}
            and type(packet["schema_version"]) is int and packet["schema_version"] == 1
            and (packet["shard"], packet["head_sha"], packet["run_id"], packet["run_attempt"]) ==
            (shard, expected.head_sha, expected.run_id, expected.run_attempt), "wrong browser shard, run or attempt")
    report = packet["report"]
    require(type(report) is dict and set(report) == set(expected.fields) | VARIABLE | {"errors", "browser", "protocol"}
            and all(report[k] == v for k, v in expected.fields.items())
            and report.get("errors") == [] and all(type(report.get(k)) is list for k in ARRAYS),
            "browser shard changed candidate, corpus, memory proof or reported an error")
    host = report.get("execution_host")
    require(type(host) is dict and host.get("platform") == "linux" and isinstance(host.get("arch"), str) and host["arch"]
            and isinstance(host.get("node"), str) and host["node"] and integer(host.get("logical_cpus"))
            and integer(host.get("memory_bytes")) and isinstance(report.get("browser"), str) and report["browser"]
            and type(report.get("protocol")) is dict and report["protocol"].get("widths") == list(WIDTHS)
            and report["protocol"].get("themes") == list(THEMES) and report["protocol"].get("independent_contexts_per_population") == 30,
            "missing browser runtime or measurement protocol")
    peak_sample(report)
    if shard == "queries":
        require(not report["populations"] and not report["component_populations"], "unexpected UI populations in queries shard")
        indices(report["cold_queries"], "sample", 100)
        indices(report["hot_queries"], "context", 3)
        for row in report["cold_queries"]:
            responses = row.get("responses")
            require(row.get("stratum") == expected.cold_strata[row["sample"] - 1]
                    and type(responses) is list and len(responses) >= 2
                    and all(type(x) is dict and integer(x.get("body_bytes")) for x in responses)
                    and integer(row.get("atlas_body_bytes")) and row["atlas_body_bytes"] == sum(x["body_bytes"] for x in responses),
                    "cold sample differs from measured transfers or frozen corpus")
        require(all(type(row.get("warmups")) is int and row["warmups"] == 1000
                    and type(row.get("samples_ms")) is list and len(row["samples_ms"]) == 1000 for row in report["hot_queries"]),
                "incomplete hot lookup sample counts")
        prefix = "browser_hot_lookup_"
    else:
        require(not report["cold_queries"] and not report["hot_queries"], "unexpected query measurements in UI shard")
        width, theme = DIMENSIONS[shard]
        for field in ("populations", "component_populations"):
            indices(report[field], "sample", 30)
            require(all(type(row.get("width")) is int and (row["width"], row.get("theme")) == (width, theme)
                        for row in report[field]), "browser population attributed to the wrong shard")
        prefix = f"browser_{width}_{theme}_"
    gates = {k: v for k, v in browser_gates(report).items() if k.startswith(prefix) or k == "worker_memory" or
             (shard == "queries" and k == "cold_payload")}
    try:
        require_all(gates)
    except ContractError as error:
        # A measured failure is more actionable than a missing result. Report
        # one class in stable gate order, never a metric, key, or exception.
        for status in ("failed", "unmeasured"):
            for key, value in gates.items():
                if value == status:
                    code = GATE_FAILURE_EXIT.get(key.removeprefix(prefix))
                    if code is not None:
                        raise BrowserGateFailure(code) from error
        raise
    return report


def join(directory, expected):
    require(directory.is_dir() and not directory.is_symlink(), "invalid browser artifact directory")
    folders = {f"atlas-browser-part-{expected.run_attempt}-{shard}": shard for shard in SHARDS}
    require({p.name for p in directory.iterdir()} == set(folders), "missing or unexpected browser shard artifacts")
    merged = None
    for folder, shard in folders.items():
        path = directory / folder
        require(path.is_dir() and not path.is_symlink() and {p.name for p in path.iterdir()} == {PART_NAME},
                "unexpected browser artifact contents")
        raw = read_data(path / PART_NAME)
        report = validate_part(json_object(raw), shard, expected)
        common = {k: v for k, v in report.items() if k not in VARIABLE}
        if merged is None:
            fixed = common
            merged = {**fixed, **{k: [] for k in ARRAYS}, "execution_host": report["execution_host"],
                      "worker_memory_samples": [], "browser_process_tree_rss_peak_bytes": 0, "measurement_shards": []}
        else:
            require(common == fixed, "browser protocol, browser version or shared evidence differs across shards")
        peak = peak_sample(report)
        # Full procfs polling histories stay in the hash-bound source artifacts.
        # Per-process clocks restart in each job. Only their peaks combine.
        merged["measurement_shards"].append({"shard": shard, "part_sha256": sha256(raw), "head_sha": expected.head_sha,
            "run_id": expected.run_id, "run_attempt": expected.run_attempt, "execution_host": report["execution_host"],
            "rss_sample_count": len(report["worker_memory_samples"])})
        merged["worker_memory_samples"].append({"shard": shard, **peak})
        merged["browser_process_tree_rss_peak_bytes"] = max(merged["browser_process_tree_rss_peak_bytes"], peak["rss_bytes"])
        for key in ARRAYS:
            merged[key].extend(report[key])
    require_all(browser_gates(merged))
    return merged


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--part", type=Path)
    source.add_argument("--directory", type=Path)
    parser.add_argument("--shard", choices=SHARDS)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.part:
        try:
            expected = identity(ROOT, os.environ)
            require(args.shard and args.output is None, "a browser part requires its expected shard ID")
            validate_part(json_object(read_data(args.part)), args.shard, expected)
        except BrowserGateFailure as error:
            return error.exit_code
        except Exception:
            # Unexpected validator errors are still a hard failure. Do not
            # emit path, argument, report, or exception diagnostics here.
            return 1
    else:
        expected = identity(ROOT, os.environ)
        require(args.shard is None and args.output, "a joined browser report requires an output path")
        result = join(args.directory, expected)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode="w", dir=args.output.parent, delete=False) as out:
            tmp = Path(out.name)
            try:
                json.dump(result, out, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
                out.write("\n")
                out.close()
                tmp.replace(args.output)
            finally:
                tmp.unlink(missing_ok=True)
    print("Verified browser measurement evidence")


if __name__ == "__main__":
    sys.exit(main())
