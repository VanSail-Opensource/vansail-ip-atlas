"""Focused synthetic acceptance examples for P0 C03/C05/C10.

These tests check the frozen math/selection contract, not a production parser,
compiler, real source coverage, hosted performance, or browser behavior.
"""

import itertools
import json
import math
from pathlib import Path
import unittest

import yaml

from tools.contract_vectors import reference


ROOT = Path(__file__).resolve().parents[2]


class ScoringContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = yaml.safe_load((ROOT / "configs/scoring.yaml").read_text(encoding="utf-8"))
        cls.vectors = json.loads((ROOT / "fixtures/scoring/contract-v1.json").read_text(encoding="utf-8"))
        cls.signals = cls.config["category_evidence"]["signals"]

    def test_coefficients_and_half_lives_unchanged(self):
        expected = {
            "malware": (2.0, 168), "botnet": (1.8, 168), "c2": (2.0, 168),
            "abuse": (1.4, 336), "fraud": (1.3, 336), "scanner": (0.9, 72),
            "spam": (0.85, 168), "tor": (0.24, 48), "vpn": (0.18, 168),
            "proxy": (0.28, 72), "cloudflare_proxyip": (0.28, 72),
            "datacenter": (0.12, 720), "hosting": (0.10, 720),
        }
        self.assertEqual(set(self.signals), set(expected))
        for signal, values in expected.items():
            self.assertEqual((self.signals[signal]["beta"], self.signals[signal]["half_life_hours"]), values)
        self.assertEqual(self.config["layers"]["weights"],
                         {"exact": 0.55, "explicit_prefix": 0.18, "asn": 0.15, "neighbors24": 0.12})

    def test_observation_vectors(self):
        for vector in self.vectors["observation"]:
            with self.subTest(vector["id"]):
                arguments = {k: vector[k] for k in ("reliability", "severity", "specificity", "age_hours", "half_life_hours")}
                if "error" in vector:
                    with self.assertRaisesRegex(ValueError, vector["error"]):
                        reference.observation(**arguments)
                else:
                    self.assertAlmostEqual(reference.observation(**arguments), vector["expected"], delta=1e-12)
        for invalid in (math.nan, math.inf, -math.inf):
            with self.assertRaises(ValueError):
                reference.observation(invalid, 1, 1, 0, 168)

    def test_layer_vectors_order_dedupe_and_monotonicity(self):
        for vector in self.vectors["layers"]:
            for permutation in itertools.permutations(vector["observations"]):
                with self.subTest(vector["id"]):
                    self.assertAlmostEqual(reference.layer(permutation, self.signals), vector["expected_risk"], delta=1e-12)
        initial = [("malware", "a", 0.8)]
        risk = reference.layer(initial, self.signals)
        for i in range(1, 20):
            next_risk = reference.layer(initial + [("malware", "b", i / 20)], self.signals)
            self.assertGreaterEqual(next_risk, risk)

    def test_coverage_and_quality_vectors(self):
        weights = list(self.config["layers"]["weights"].values())
        for vector in self.vectors["quality"]:
            with self.subTest(vector["id"]):
                self.assertEqual(reference.quality(vector["ipv4"], vector["layers"], vector["complete_families"], weights),
                                 (vector["expected_score"], vector["expected_confidence"]))

    def test_asn_vectors_and_moas_max(self):
        contributions = []
        for vector in self.vectors["asn"]:
            values = reference.asn_context(vector["risks"], vector["families"], vector["explicit_risk"])
            contributions.append(values[2])
            for actual, key in zip(values, ("expected_risk", "expected_confidence", "expected_weighted")):
                self.assertAlmostEqual(actual, vector[key], delta=1e-12)
        self.assertEqual(max(contributions), contributions[0])
        self.assertLessEqual(reference.asn_context([1] * 100000, 20, 1)[2], 0.15)
        self.assertEqual(reference.asn_context([], 0, 0)[2], 0)

    def test_neighbor_vectors_and_cap(self):
        for vector in self.vectors["neighbor"]:
            values = reference.neighbor(vector["query"], vector["observations"])
            for actual, key in zip(values, ("expected_density", "expected_risk", "expected_confidence")):
                self.assertAlmostEqual(actual, vector[key], delta=1e-12)
        observations = [(f"192.0.2.{i}", 1, f"family-{i % 3}") for i in range(256)]
        _, risk, support = reference.neighbor("192.0.2.1", observations)
        self.assertLessEqual(0.12 * support * risk, 0.12)

    def test_geo_support_margin_and_family_abstention(self):
        for vector in self.vectors["geo"]:
            with self.subTest(vector["id"]):
                self.assertEqual(reference.geo_vote(vector["votes"], vector["min_support"]), vector["expected"])


class BGPContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = yaml.safe_load((ROOT / "configs/tier1.yaml").read_text(encoding="utf-8"))
        cls.vectors = json.loads((ROOT / "fixtures/bgp/contract-v1.json").read_text(encoding="utf-8"))

    def test_existing_thresholds_preserved_and_mrt_disabled(self):
        config = self.config["classification"]
        self.assertEqual(config["peer_clique_support_threshold"], 0.80)
        self.assertEqual(config["customer_cone_percentile_threshold"], 0.98)
        self.assertEqual(config["transit_degree_percentile_threshold"], 0.98)
        self.assertEqual(config["minimum_independent_observation_families"], 2)
        sources = yaml.safe_load((ROOT / "configs/sources.yaml").read_text(encoding="utf-8"))
        self.assertFalse(sources["build"]["bgp"]["mrt_enabled"])
        self.assertGreaterEqual(sources["build"]["bgp"]["max_mrt_sources_per_run"], 2)
        self.assertNotIn("provider_transit", sources["build"]["bgp"]["relationship_classes"])

    def test_reverse_relationship_perspective(self):
        for vector in self.vectors["relationships"]:
            self.assertEqual(reference.relationship(vector["provider"], vector["customer"], vector["from"], vector["to"]), vector["expected"])

    def test_percentiles_and_peer_core(self):
        for vector in self.vectors["percentiles"]:
            self.assertEqual(reference.percentile98(vector["values"]), vector["expected_p98"])
        for vector in self.vectors["peer_cores"]:
            for nodes in (vector["nodes"], list(reversed(vector["nodes"]))):
                self.assertEqual(reference.peer_core(nodes, vector["peers"]), vector["expected"])

    def test_missing_bootstrap_stale_policy_and_stability(self):
        for vector in self.vectors["stability"]:
            arguments = {k: vector[k] for k in ("current", "previous", "separation_hours", "same_policy", "eligible")}
            self.assertEqual(reference.stable_candidate(**arguments), vector["expected"])
        self.assertEqual(len(set(["ris", "ris"])), 1)  # two collectors do not make two families

    def test_graph_budget_continuity_protected_hops_and_exits(self):
        routes = [[100, 200, 300] + list(range(400, 440)),
                  [100, 201, 301, 900, 901], [100, 202, 302, 902]]
        projected = reference.graph_projection(routes)
        self.assertLessEqual(len({n for route in projected for n in route}), 24)
        for original, visible in zip(routes, projected):
            self.assertEqual(visible[:3], original[:3])
            self.assertEqual(visible, original[:len(visible)])
        exits = [[100, 200, 300, exit_asn] for exit_asn in (400, 401, 402, 403)]
        visible = reference.graph_projection(exits)
        self.assertEqual([len(p) for p in visible], [4, 4, 4, 3])
        overflow = [[100, 200 + i, 300 + i] for i in range(20)]
        visible = reference.graph_projection(overflow)
        self.assertLessEqual(len({n for route in visible for n in route}), 24)
        self.assertTrue(all(len(p) == 3 for p in visible))
        self.assertEqual(reference.graph_projection([[100, 200, 100]]), [])

    def test_rpki_moas_origin_maximum_length_and_unavailable(self):
        vrps = [("192.0.2.0/24", 24, 100)]
        self.assertEqual(reference.rpki("192.0.2.0/24", 100, vrps), "valid")
        self.assertEqual(reference.rpki("192.0.2.0/24", 200, vrps), "invalid")
        self.assertEqual(reference.rpki("192.0.2.0/25", 100, vrps), "invalid")
        self.assertEqual(reference.rpki("198.51.100.0/24", 100, vrps), "not_found")
        self.assertEqual(reference.rpki("192.0.2.0/24", 100, None), "unknown")


if __name__ == "__main__":
    unittest.main()
