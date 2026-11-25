import copy
import json
from pathlib import Path
import tempfile
import unittest

from tools.hosted import preview_shards as shards
from tools.release_contract.contracts import ContractError
from tools.release_contract.test_acceptance import browser_report, graph


def fixture(root):
    def write(path, obj):
        path.parent.mkdir(exist_ok=True, parents=True)
        path.write_text(json.dumps(obj, separators=(",", ":")))
    env = {"GITHUB_SHA": "a" * 40, "GITHUB_RUN_ID": "623", "GITHUB_RUN_ATTEMPT": "2"}
    report = browser_report()
    prefix = "https://abcdef12.vansail-ip-atlas.pages.dev"
    evidence = root / "reports"
    candidate = {"mode": "production", "status": "passed", "qualification_receipt_sha256": "9" * 64,
                 "release_id": report["release_id"], "candidate_bundle_sha256": report["candidate_bundle_sha256"]}
    write(evidence / "static-candidate.json", candidate)
    write(evidence / "pages-deployment.json", {**candidate, "status": "verified", "operation": "preview",
        "environment": "preview", "url": prefix, "head_sha": env["GITHUB_SHA"],
        "deployment_id": "abcdef12-aaaa-bbbb-cccc-000000000000"})
    memory = {**report["worst_case_worker_memory"], "accounting": "isolated-cgroup-v2-memory.peak",
        "profile_exercised": "accepted-worst-case-browser-profile", "peak_bytes": 12345, "raw_profile_sha256": "e"*64,
        "includes_worker_children": True, "errors": [], "accounting_scope": "entire-Chrome-tree-from-process-birth",
        "memory_events": {"oom_kill": 0}}
    write(evidence / "worker-memory.json", memory)
    write(root / ".atlas-private/production-browser-corpus.json", {"format_version": 3, "mode": "production",
          "release_id": report["release_id"], "availability": report["corpus_availability"],
          "ipv4_network_coverage": None, "map_query": None, "graph_query": None,
          "queries": [{"q": "192.0.2.1", "stratum": "ipv4_lpm"}, {"q": "AS123", "stratum": "unknown"}] * 5000})
    return shards.identity(root, env)


def part(expected, shard):
    report = {**browser_report(), **expected.fields, "browser": "158.0.0.1",
        "protocol": {"widths": list(shards.WIDTHS), "themes": list(shards.THEMES), "independent_contexts_per_population": 30},
        "execution_host": {"platform": "linux", "arch": "x64", "node": "26.13.1", "logical_cpus": 4, "memory_bytes": 8 << 30},
        "cold_queries": [], "hot_queries": [],
        "worker_memory_samples": [{"supported": True, "at_ms": 400, "rss_bytes": 200, "processes": 3}],
        "browser_process_tree_rss_peak_bytes": 200}
    if shard == "queries":
        report["cold_queries"] = [{"sample": i, "stratum": expected.cold_strata[i-1], "atlas_body_bytes": 180,
            "responses": [{"path": "/_atlas/current.json", "body_bytes": 100},
                          {"path": "/_atlas/releases/x/manifest.json", "body_bytes": 50},
                          {"path": "/dataset-credits.json", "body_bytes": 12},
                          {"path": "/_atlas/credits/" + "b"*64 + ".json", "body_bytes": 18}]} for i in range(1, 101)]
        report["hot_queries"] = [{"context": i, "warmups": 1000, "samples_ms": [3] * 1000,
                                  "timing": "actual-worker-indexed-lookups"} for i in range(1, 4)]
    else:
        width, theme = shards.DIMENSIONS[shard]
        g = graph()
        axe = {"engine": "axe-core", "violations": [], "incomplete": []}
        for i in range(1, 31):
            identity = {"width": width, "theme": theme, "sample": i}
            report["populations"].append({**identity, "complete_interaction_script": True, "event_timing_supported": True,
                "completed_routes": ["overview", "quality", "class-c", "asn", "bgp"], "interaction_durations_ms": [16],
                "lcp_ms": 999, "initial_js_gzip_bytes": 1024, "interaction_cls": 0, "accessibility": axe,
                "map": {"state": "unavailable", "unknown_state_verified": True}, "graph": {"state": "unavailable",
                "visible_nodes": 0, "observed_routes": 0, "empty_state_verified": True},
                "unknown_states": {"ipv4": True, "ipv6": True, "asn": True}, "ipv4_network_coverage_verified": None})
            report["component_populations"].append({**identity, "worker_sha256": report["worst_case_worker_memory"]["worker_sha256"],
                "ipv4_unknown_state_verified": True, "graph": g, "accessibility": axe})
    return {"schema_version": 1, "shard": shard, "head_sha": expected.head_sha,
            "run_id": expected.run_id, "run_attempt": expected.run_attempt, "report": report}


class BrowserShardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.identity = fixture(self.root)

    def test_join_all_measured_populations_and_their_own_rss_peaks(self):
        directory = self.root / "parts"
        for i, shard in enumerate(shards.SHARDS):
            packet = part(self.identity, shard)
            report = packet["report"]
            report["execution_host"]["memory_bytes"] += i
            peak = 203 + i
            report["worker_memory_samples"].append({"supported": True, "at_ms": 800, "rss_bytes": peak, "processes": 4})
            report["browser_process_tree_rss_peak_bytes"] = peak
            folder = directory / f"atlas-browser-part-2-{shard}"
            folder.mkdir(parents=True)
            (folder / shards.PART_NAME).write_text(json.dumps(packet, separators=(",", ":")))
        result = shards.join(directory, self.identity)
        self.assertEqual([len(result[k]) for k in shards.ARRAYS], [240, 240, 100, 3])
        self.assertEqual(result["browser_process_tree_rss_peak_bytes"], 211)
        self.assertEqual([r["rss_bytes"] for r in result["worker_memory_samples"]], list(range(203, 212)))
        self.assertTrue(all(r["rss_sample_count"] == 2 for r in result["measurement_shards"]))
        self.assertEqual([r["shard"] for r in result["measurement_shards"]], list(shards.SHARDS))
        # A complete set of filenames is insufficient when an artifact belongs to another shard.
        file = directory / "atlas-browser-part-2-320-light" / shards.PART_NAME
        file.write_text(json.dumps(part(self.identity, "320-dark")))
        with self.assertRaisesRegex(ContractError, "wrong browser shard"):
            shards.join(directory, self.identity)

    def test_partial_reports_cannot_substitute_samples_or_measurements(self):
        packet = part(self.identity, "320-light")
        cases = [
            lambda p: p.update(run_attempt="1"), lambda p: p.update(head_sha="b"*40),
            lambda p: p.update(run_id="624"), lambda p: p.update(schema_version=True),
            lambda p: p["report"].update(errors=["page exception"]),
            lambda p: p["report"].update(url="https://bbbbbbbb.vansail-ip-atlas.pages.dev"),
            lambda p: p["report"].update(qualification_receipt_sha256="8"*64),
            lambda p: p["report"].update(corpus_sha256="8"*64),
            lambda p: p["report"]["worst_case_worker_memory"].update(peak_bytes=1),
            lambda p: p["report"]["component_populations"][7].update(sample=7),
            lambda p: p["report"]["populations"][0].update(sample=31),
            lambda p: p["report"]["populations"][2].update(theme="dark"),
            lambda p: p["report"]["cold_queries"].append({"sample": 1}),
            lambda p: p["report"].update(browser_process_tree_rss_peak_bytes=199),
            lambda p: p["report"]["populations"][0].update(interaction_cls=.1)]
        for i, change in enumerate(cases):
            with self.subTest(i=i), self.assertRaises(ContractError):
                broken = copy.deepcopy(packet)
                change(broken)
                shards.validate_part(broken, "320-light", self.identity)

    def test_exact_query_ids_corpus_transfer_bytes_and_timed_calls(self):
        packet = part(self.identity, "queries")
        shards.validate_part(packet, "queries", self.identity)
        for mutate in (lambda r: r["cold_queries"][0].update(sample=2),
                       lambda r: r["cold_queries"][0].update(stratum="unknown"),
                       lambda r: r["cold_queries"][0].update(atlas_body_bytes=1),
                       lambda r: r["hot_queries"][0].update(context=4),
                       lambda r: r["hot_queries"][0].update(warmups=999),
                       lambda r: r["hot_queries"][0]["samples_ms"].pop(),
                       lambda r: r["hot_queries"][1].update(samples_ms=[15]*1000),
                       lambda r: r["component_populations"].append({"sample": 1})):
            with self.subTest(mutate=mutate), self.assertRaises(ContractError):
                broken = copy.deepcopy(packet)
                mutate(broken["report"])
                shards.validate_part(broken, "queries", self.identity)

    def test_only_attempt_specific_artifact_tree_accepted(self):
        directory = self.root / "parts"
        directory.mkdir()
        for name in ("atlas-browser-part-1-queries", "atlas-browser-part-2-queries"):
            (directory / name).mkdir()
        with self.assertRaisesRegex(ContractError, "missing or unexpected"):
            shards.join(directory, self.identity)
