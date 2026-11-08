"""Independent P0 audit regressions for clock and capability qualification.

The capability tests isolate the report's classification predicates from the
separate admission verifier; no synthetic record is added to the real catalog.
"""

import copy
import unittest
from unittest.mock import patch

from tools.atlas_contracts.config import ContractError, ROOT, load_configs, safe_https, validate_sources
from tools.atlas_contracts.policy import capability_report, utc


class SourcePolicyAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = load_configs()["sources"]

    def test_utc_rejects_ambiguous_naive_or_noncanonical_clock(self):
        for value in ("2026-11-08Z", "2026-11-08 00:00:00Z", "2026-W45-7T00:00:00Z",
                      "2026-11-08T00:00Z", "2026-11-08T00:00:00+08:00Z"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                utc(value)
        self.assertEqual(utc("2026-11-08T00:00:00.000001Z").microsecond, 1)

    def test_literal_private_and_ambiguous_url_rejected_before_fetch(self):
        for value in ("https://127.0.0.1/x", "https://[::1]/x", "https://10.0.0.1/x",
                      "https://169.254.169.254/x", "https://example.com/\nasset",
                      "https://224.0.0.1/x", "https://[ff02::1]/x", "https://2130706433/x",
                      "https://0x7f.0x0.0x0.0x1/x",
                      "https://0177.0.0.1/x", "https://@example.com/x", "https://example.com:/x",
                      "https://127%2e0%2e0%2e1/x", "https://[fe80::1%25eth0]/x"):
            with self.subTest(value=value):
                self.assertFalse(safe_https(value))
        self.assertTrue(safe_https("https://8.8.8.8/payload"))
        self.assertTrue(safe_https("https://api.github.com/repos/example/project/commits?path=data.txt", allow_query=True))
        self.assertFalse(safe_https("https://api.github.com/repos/example/project/commits?path=data.txt"))

    def test_all_fetchable_metadata_url_fields_are_checked(self):
        for field in ("discovery", "license", "publication_proof"):
            invalid = copy.deepcopy(self.catalog)
            source = invalid["sources"][0]
            if field == "discovery":
                source[field] = {"mode": "latest-timestamped-asset", "requires_exact_file": True,
                                 "index_url": "https://127.0.0.1/index"}
            elif field == "license":
                source[field]["evidence_url"] = "https://127.0.0.1/rights"
            else:
                source[field]["locator"] = "https://127.0.0.1/metadata"
            with self.subTest(field=field), self.assertRaises(ContractError):
                validate_sources(invalid)

    def source(self, sid, category="geolocation", fields=(), scope="prefix", coverage="mapping"):
        source = copy.deepcopy(self.catalog["sources"][0])
        source.update(id=sid, evidence_family=sid, admission="active", category=category,
                      public_fields=list(fields), scope=scope, signals=[])
        source["coverage"] = {"kind": coverage, "scope": scope}
        source["depends_on"] = []
        return source

    def report(self, sources, states=None):
        states = states or {}
        with patch("tools.atlas_contracts.policy.static_issues", return_value=[]), patch(
            "tools.atlas_contracts.policy.runtime_state",
            side_effect=lambda source, *args: (states.get(source["id"], "current"), [])
        ):
            return capability_report({"sources": sources}, utc("2026-11-08T00:00:00Z"), ROOT)

    @staticmethod
    def capability(report, name):
        return next(row for row in report["capabilities"] if row["capability"] == name)["status"]

    def test_noncurrent_dependency_prevents_child_capability(self):
        parent = self.source("mapping-parent", fields=("origins",))
        child = self.source("usage-child", category="infrastructure", fields=("usage_type",), scope="exact_ip")
        child["depends_on"] = [parent["id"]]
        for state in ("missing", "stale", "invalid", "quarantined"):
            report = self.report([parent, child], {parent["id"]: state})
            with self.subTest(state=state):
                self.assertEqual(self.capability(report, "usage"), "blocked")

    def test_city_positive_only_never_qualifies_mapping(self):
        sources = [self.source(f"geo-{i}", fields=("physical_country", "region", "city", "latitude", "longitude"), coverage="positive_only")
                   for i in range(2)]
        report = self.report(sources)
        self.assertEqual(self.capability(report, "region_city"), "blocked")
        self.assertEqual(self.capability(report, "coordinates"), "blocked")

    def test_declared_public_field_does_not_create_vrp_capability(self):
        source = self.source("geo-with-rpki-label", fields=("rpki_status",))
        self.assertEqual(self.capability(self.report([source]), "rpki"), "blocked")

    def test_assessment_layer_must_match_scope(self):
        invalid = copy.deepcopy(self.catalog)
        source = invalid["sources"][0]
        source["coverage"]["kind"] = "complete"
        source["assessment_layers"] = ["exact"]
        self.assertEqual(source["scope"], "prefix")
        with self.assertRaises(ContractError):
            validate_sources(invalid)

    def test_numeric_quality_rejects_asn_scope_relabelled_as_all_layers(self):
        sources = []
        for family in ("family-a", "family-b"):
            for layer in ("exact", "explicit_prefix", "asn", "neighbors24"):
                source = self.source(f"{family}-{layer}", category="abuse", fields=("reason_flags",),
                                     scope="asn", coverage="complete")
                source.update(evidence_family=family, assessment_layers=[layer], signals=["abuse"])
                sources.append(source)
        report = self.report(sources)
        self.assertEqual(self.capability(report, "numeric_quality"), "unrated")
        row = next(row for row in report["capabilities"] if row["capability"] == "numeric_quality")
        self.assertFalse(row["required"])
        self.assertEqual(row["families"], [])

    def test_optional_numeric_quality_still_qualifies_only_two_complete_families(self):
        sources = []
        for family in ("family-a", "family-b"):
            for layer, scope in (("exact", "exact_ip"), ("neighbors24", "exact_ip"), ("explicit_prefix", "prefix"), ("asn", "asn")):
                source = self.source(f"{family}-{layer}", category="abuse", fields=("reason_flags",), scope=scope, coverage="complete")
                source.update(evidence_family=family, assessment_layers=[layer], signals=["abuse"])
                sources.append(source)
        report = self.report(sources)
        row = next(row for row in report["capabilities"] if row["capability"] == "numeric_quality")
        self.assertEqual(row["status"], "qualified")
        self.assertFalse(row["required"])
        self.assertEqual(row["families"], ["family-a", "family-b"])
        # Optional scoring cannot waive unrelated data or Pages evidence.
        self.assertFalse(report["production_eligible"])
        self.assertEqual(self.capability(report, "rpki"), "blocked")
        self.assertEqual(self.capability(report, "pages_release"), "blocked")

    def test_positive_only_risk_does_not_become_clean_or_a_release_requirement(self):
        source = self.source("positive-only", category="abuse", fields=("reason_flags",), scope="exact_ip", coverage="positive_only")
        source["signals"] = ["abuse"]
        report = self.report([source])
        row = next(row for row in report["capabilities"] if row["capability"] == "numeric_quality")
        self.assertEqual(row["status"], "unrated")
        self.assertEqual(row["families"], [])
        self.assertFalse(row["required"])
        self.assertNotIn("abuse", report["missing_reason_evidence"])
        self.assertEqual(report["required_capability_count"], 12)


if __name__ == "__main__":
    unittest.main()
