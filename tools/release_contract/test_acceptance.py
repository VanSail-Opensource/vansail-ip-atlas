import copy
import unittest

from tools.release_contract.acceptance import CORPUS_STRATA, GRAPH_FIXTURE_SHA256, allocation_gate, browser_gates, build_gates, comparison, graph_gate, require_all
from tools.release_contract.contracts import ContractError


def graph():
    box = {"left": 0, "top": 0, "right": 100, "bottom": 100}
    population = {"svg_bounds": box, "visible_bounds": box,
                  "circles": [{"left": 2, "top": 2, "right": 4, "bottom": 4} for _ in range(24)]}
    return {"visible_nodes": 24, "active_frames": [{"action": name, "duration_ms": 10_000,
        "actions": 100, "complete_second_fps": [60] * 10,
        "population_checkpoints": [copy.deepcopy(population) for _ in range(12)]}
        for name in ("keyboard-pan", "wheel-zoom", "route-focus")]}


def browser_report():
    return {"scope": "hosted-production-browser-v3", "release_scope": "release-scope-v6", "mode": "production",
        "errors": [], "release_id": "a" * 64, "corpus_release_id": "a" * 64, "corpus_sha256": "b" * 64,
        "corpus_ipv4_network_coverage": None, "candidate_bundle_sha256": "c" * 64, "corpus_features": {"map": False, "graph": False},
        "corpus_availability": [{"stratum": s, "status": "observed" if s in ("ipv4_lpm", "unknown") else "absent",
            "sampled_queries": 1 if s in ("ipv4_lpm", "unknown") else 0} for s in CORPUS_STRATA],
        "populations": [], "component_populations": [], "worst_case_worker_memory": {"worker_sha256": "d" * 64},
        "graph_component_fixture": {"scope": "isolated-synthetic-capacity", "fixture_sha256": GRAPH_FIXTURE_SHA256,
            "candidate_bundle_sha256": "c" * 64, "worker_sha256": "d" * 64}}


class AcceptanceTests(unittest.TestCase):
    def test_cold_payload_recomputes_complete_response_population(self):
        report = browser_report()
        responses = [{"path": path, "body_bytes": 10} for path in
                     ("/_atlas/current.json", "/dataset-credits.json", "/_atlas/credits/" + "a" * 64 + ".json")]
        report["cold_queries"] = [{"responses": copy.deepcopy(responses), "atlas_body_bytes": 30} for _ in range(100)]
        self.assertEqual(browser_gates(report)["cold_payload"], "passed")
        report["cold_queries"][0]["responses"][0]["body_bytes"] += 1
        self.assertEqual(browser_gates(report)["cold_payload"], "unmeasured")
        report["cold_queries"][0] = {"responses": responses[:-1], "atlas_body_bytes": 20}
        self.assertEqual(browser_gates(report)["cold_payload"], "unmeasured")
        for row in report["cold_queries"]:
            row["responses"] = [*responses, {"path": "/_atlas/objects/" + "b" * 64 + ".via3", "body_bytes": 400 * 1024 - 30}]
            row["atlas_body_bytes"] = 400 * 1024
        self.assertEqual(browser_gates(report)["cold_payload"], "failed")

    def test_go_allocation_gate_requires_actual_complete_process_population(self):
        row={'compile_exit_code':0,'allocation_scope':'all-atlas-Go-processes-in-scenario',
            'go_processes':[],'go_invocations':[],'allocation_count':0,'allocated_bytes':0,'allocation_process_count':0}
        for index,phase in enumerate(('intake','state-fingerprints','compile-production','prepare-static'),1):
            token=f'{index:032x}'
            expected={phase:1} if phase!='prepare-static' else {'inspect':1,'verify-production':2}
            row['go_invocations'].append({'invocation':token,'phase':phase,'root_pid':index,'exit_code':0,'expected_commands':expected})
            for command,count in expected.items():
                for item in range(count):
                    pid=index if phase!='prepare-static' else 100+len(row['go_processes'])
                    row['go_processes'].append({'allocated_bytes':1000,'allocation_count':100,'command':command,
                        'exit_code':0,'invocation':token,'pid':pid,'schema_version':1,'scope':'atlas-go-runtime-allocations-v1'})
        row.update(allocation_count=600,allocated_bytes=6000,allocation_process_count=6)
        self.assertEqual(allocation_gate(row),'passed')
        failed=copy.deepcopy(row)
        failed['compile_exit_code']=1
        failed['go_invocations'].pop()
        failed['go_processes']=failed['go_processes'][:3]
        failed['go_invocations'][-1]['exit_code']=failed['go_processes'][-1]['exit_code']=1
        failed.update(allocation_count=300,allocated_bytes=3000,allocation_process_count=3)
        self.assertEqual(allocation_gate(failed),'passed')
        for mutation in ('missing','nil','sum','scope','pid','duplicate','invocation'):
            invalid=copy.deepcopy(row)
            if mutation=='missing':invalid['go_processes'].pop()
            elif mutation=='nil':invalid['allocation_count']=None
            elif mutation=='sum':invalid['allocation_count']+=1
            elif mutation=='scope':invalid['allocation_scope']='unmeasured'
            elif mutation=='pid':invalid['go_processes'][0]['pid']+=1
            elif mutation=='duplicate':invalid['go_processes'].append(copy.deepcopy(invalid['go_processes'][0]))
            elif mutation=='invocation':invalid['go_processes'][0]['invocation']='f'*32
            with self.subTest(mutation=mutation):self.assertEqual(allocation_gate(invalid),'unmeasured')

    def test_policy_flags_and_synthetic_diagnostics_cannot_satisfy_real_gates(self):
        with self.assertRaises(ContractError):
            browser_gates({"scope": "hosted-synthetic-measurements", "hosted_gate_passed": True})
        with self.assertRaises(ContractError):
            require_all({"memory": "unmeasured", "lcp": "passed"})

    def test_strict_thresholds_and_nonfinite_missing_or_bool_samples(self):
        self.assertEqual(comparison([199.99], 200), "passed")
        self.assertEqual(comparison([200], 200), "failed")
        for value in (True, None, float('nan'), float('inf')):
            self.assertEqual(comparison([value], 200), "unmeasured")
        self.assertEqual(comparison([1], 200, minimum=2), "unmeasured")

    def test_physical_population_and_every_second_cannot_be_replaced_by_dom_count(self):
        data = graph()
        self.assertEqual(graph_gate(data), "passed")
        data["active_frames"][1]["complete_second_fps"][5] = 49
        self.assertEqual(graph_gate(data), "failed")
        data = graph()
        data["active_frames"][0]["population_checkpoints"][1]["circles"][0]["right"] = 101
        self.assertEqual(graph_gate(data), "failed")
        data = graph()
        data["active_frames"][0]["population_checkpoints"] = []
        self.assertEqual(graph_gate(data), "unmeasured")

    def test_missing_theme_populations_heap_memory_and_fast_batch_mean_stay_unmeasured(self):
        report = browser_report()
        report["worst_case_worker_memory"] = {"accounting": "JSHeapUsedSize", "peak_bytes": 100_000}
        browser = browser_gates(report)
        self.assertTrue(browser)
        self.assertTrue(all(value == "unmeasured" for value in browser.values()))
        build = build_gates({"scope": "hosted-production-build-v1", "mode": "production", "errors": [],
            "execution_host": {"logical_cpus": 4, "memory_bytes": 16 * 1024**3, "disk_bytes": 90 * 1024**3},
            "scenarios": [], "go_lookup": {"batch_mean_ns": 1000}})
        self.assertEqual(build["standard_runner"], "unmeasured")
        self.assertEqual(build["go_lookup_p95"], "unmeasured")
        self.assertEqual(build["cold_full_go_allocations"], "unmeasured")

    def test_duplicate_population_cannot_manufacture_sample_count(self):
        sample = {"width": 320, "theme": "light", "sample": 1}
        report = browser_report()
        report["populations"] = [sample, sample]
        with self.assertRaises(ContractError):
            browser_gates(report)

    def test_verified_unknowns_do_not_replace_full_graph_capacity_populations(self):
        report = browser_report()
        for width in (320, 390, 1280, 1440):
            for theme in ("light", "dark"):
                for sample in range(1, 31):
                    identity = {"width": width, "theme": theme, "sample": sample}
                    report["populations"].append({**identity, "lcp_ms": 100, "initial_js_gzip_bytes": 100,
                        "interaction_cls": 0, "interaction_durations_ms": [16], "complete_interaction_script": True,
                        "completed_routes": ["overview", "quality", "class-c", "asn", "bgp"], "event_timing_supported": True,
                        "accessibility": {"engine": "axe-core", "violations": [], "incomplete": []},
                        "map": {"state": "not_displayed", "hidden_verified": True},
                        "graph": {"state": "unavailable", "visible_nodes": 0, "observed_routes": 0, "empty_state_verified": True},
                        "ipv4_network_coverage_verified": None, "unknown_states": {"ipv4": True, "ipv6": True, "asn": True}})
                    report["component_populations"].append({**identity, "ipv4_unknown_state_verified": True, "worker_sha256": "d" * 64, "graph": graph(),
                        "accessibility": {"engine": "axe-core", "violations": [], "incomplete": []}})
        gates = browser_gates(report)
        self.assertTrue(all(value == "passed" for key, value in gates.items() if key.startswith("browser_320_light_")))
        report["corpus_features"] = {"map": True, "graph": True}
        for row in report["populations"]:
            # Nonlinear observed paths can be retained while projecting no SVG nodes.
            row["graph"] = {"state": "observed", "visible_nodes": 0, "observed_routes": 2, "empty_state_verified": False}
        self.assertEqual(browser_gates(report)["browser_320_light_candidate_states"], "passed")
        for invalid in (
            {},
            {"state": "observed", "unknown_state_verified": False},
            {"state": "not_displayed", "hidden_verified": 1},
        ):
            with self.subTest(map_evidence=invalid):
                report["populations"][0]["map"] = invalid
                self.assertEqual(browser_gates(report)["browser_320_light_candidate_states"], "unmeasured")
        report["populations"][0]["map"] = {"state": "not_displayed", "hidden_verified": True}
        report["populations"][0]["graph"]["observed_routes"] = 0
        self.assertEqual(browser_gates(report)["browser_320_light_candidate_states"], "unmeasured")
        report["corpus_features"] = {"map": False, "graph": False}
        for row in report["populations"]:
            row["graph"] = {"state": "unavailable", "visible_nodes": 0, "observed_routes": 0, "empty_state_verified": True}
        report["component_populations"][0]["graph"] = {"visible_nodes": 0, "active_frames": []}
        self.assertEqual(browser_gates(report)["browser_320_light_graph"], "unmeasured")
        report["component_populations"][0]["graph"] = graph()
        report["component_populations"][0]["graph"]["active_frames"][0]["complete_second_fps"][0] = 49
        self.assertEqual(browser_gates(report)["browser_320_light_graph"], "failed")
        report["component_populations"][0]["graph"] = graph()
        report["graph_component_fixture"]["worker_sha256"] = "e" * 64
        self.assertEqual(browser_gates(report)["browser_320_light_graph"], "unmeasured")
        report["graph_component_fixture"]["worker_sha256"] = "d" * 64
        report["component_populations"][0]["accessibility"]["incomplete"] = [{"id": "color-contrast"}]
        self.assertEqual(browser_gates(report)["browser_320_light_accessibility"], "unmeasured")
        report["component_populations"][0]["accessibility"]["violations"] = [{"id": "color-contrast"}]
        self.assertEqual(browser_gates(report)["browser_320_light_accessibility"], "failed")
        report["populations"][0]["graph"]["visible_nodes"] = 1
        self.assertEqual(browser_gates(report)["browser_320_light_candidate_states"], "unmeasured")
        report["populations"][0]["unknown_states"]["ipv4"] = 1
        self.assertEqual(browser_gates(report)["browser_320_light_ipv4_unknown_state"], "unmeasured")

        report["corpus_ipv4_network_coverage"] = {"covered_addresses": 2**32, "network_objects": 1, "router_intervals": 2}
        gates = browser_gates(report)
        self.assertNotIn("browser_320_light_ipv4_unknown_state", gates)
        self.assertEqual(gates["browser_320_light_ipv4_network_coverage"], "unmeasured")
        for row in report["populations"]:
            row["unknown_states"]["ipv4"] = None
            row["ipv4_network_coverage_verified"] = True
        self.assertEqual(browser_gates(report)["browser_320_light_ipv4_network_coverage"], "passed")
        report["populations"][0]["unknown_states"]["ipv6"] = False
        self.assertEqual(browser_gates(report)["browser_320_light_ipv6_asn_unknown_states"], "unmeasured")
        report["component_populations"][0]["ipv4_unknown_state_verified"] = None
        self.assertEqual(browser_gates(report)["browser_320_light_synthetic_ipv4_unknown_state"], "unmeasured")
        for invalid in ({"covered_addresses": 2**32-1, "network_objects": 1, "router_intervals": 1},
                        {"covered_addresses": 2**32, "network_objects": True, "router_intervals": 1},
                        {"covered_addresses": 2**32, "network_objects": 2, "router_intervals": 1}):
            report["corpus_ipv4_network_coverage"] = invalid
            with self.assertRaises(ContractError): browser_gates(report)

    def test_corpus_absence_and_candidate_identity_cannot_be_asserted_by_flags(self):
        for mutation in ("count", "status", "release", "scope", "duplicate"):
            report = browser_report()
            if mutation == "count": report["corpus_availability"][0]["sampled_queries"] = True
            elif mutation == "status": report["corpus_availability"][0]["status"] = "observed"
            elif mutation == "release": report["corpus_release_id"] = "e" * 64
            elif mutation == "scope": report["release_scope"] = "release-scope-v5"
            elif mutation == "duplicate": report["corpus_availability"][0] = report["corpus_availability"][1]
            with self.subTest(mutation=mutation), self.assertRaises(ContractError): browser_gates(report)

    def test_overshoot_one_build_sample_fails_maximum_gate(self):
        data = {"scope": "hosted-production-build-v1", "mode": "production", "errors": [],
                "execution_envelope": {'scope':'github-hosted-cgroup-v2','cpu_quota_us':200000,
                    'cpu_period_us':100000,'memory_max_bytes':8*1024**3,'swap_max_bytes':0,'workspace_limit_bytes':14*1024**3},
                "execution_host": {"logical_cpus": 2, "memory_bytes": 8 * 1024**3, "disk_bytes": 14 * 1024**3},
                "scenarios": [{"scenario": "cold_full", "runtime_ms": value,
                    "process_group_peak_rss_bytes": 100, "scratch_peak_bytes": 100}
                    for value in (1, 1, 35 * 60_000)]}
        gates = build_gates(data)
        self.assertEqual(gates["standard_runner"], "passed")
        self.assertEqual(gates["cold_full_runtime"], "failed")

    def test_runner_claims_without_kernel_envelope_are_not_capacity_evidence(self):
        report={'scope':'hosted-production-build-v1','mode':'production','errors':[],
            'execution_host':{'logical_cpus':2,'memory_bytes':8*1024**3,'disk_bytes':14*1024**3}}
        self.assertEqual(build_gates(report)['standard_runner'],'unmeasured')

    def test_real_transition_counts_and_exact_baseline_corpus_are_required(self):
        state, release = 'a' * 64, 'b' * 64
        rows = []
        for name in ('cold_full','warm_changed','warm_unchanged','clock_advance','withdrawal'):
            for sample in (1,2,3):
                before,after,added,removed = (0,100,100,0) if name=='cold_full' else (100,100,1,1) if name=='warm_changed' else (100,100,0,0) if name=='warm_unchanged' else (100,90,0,10)
                rows.append({'scenario':name,'sample':sample,'runtime_ms':100,'process_group_peak_rss_bytes':100,'scratch_peak_bytes':100,
                    'compile_exit_code':0,'release_id':release,'before_state_sha256':state,'after_state_sha256':state,
                    'transition':{'before_records':before,'after_records':after,'added_records':added,'removed_records':removed,
                        'changed_records':max(added,removed),'expired_sources_retracted':1,'withdrawn_sources_retracted':1}})
        report={'scope':'hosted-production-build-v1','mode':'production','errors':[],
            'execution_host':{'logical_cpus':2,'memory_bytes':8*1024**3,'disk_bytes':14*1024**3},
            'release_id':release,'normalized_state_sha256':state,'scenarios':rows}
        self.assertEqual(build_gates(report)['warm_changed_actual_transition'],'passed')
        report['scenarios'][3]['transition']['changed_records']=2
        self.assertEqual(build_gates(report)['warm_changed_actual_transition'],'unmeasured')
        report['scenarios'][3]['transition']['changed_records']=1
        report['scenarios'][3]['before_state_sha256']='c'*64
        self.assertEqual(build_gates(report)['warm_changed_actual_transition'],'unmeasured')


if __name__ == "__main__":
    unittest.main()
