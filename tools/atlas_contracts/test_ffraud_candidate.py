import copy
import unittest

from tools.atlas_contracts.config import ContractError, ROOT, load_yaml, validate_schema, validate_sources
from tools.atlas_contracts.policy import capability_report, utc


class FFraudCandidateTests(unittest.TestCase):
    def setUp(self):
        self.config = load_yaml(ROOT / "configs/sources.yaml")
        self.source = next(source for source in self.config["sources"] if source["id"] == "ffraud-ip")
        # Test the new inactive source independently of the unrelated active
        # sources' implementation-bound certificates, which root refreshes only
        # after all compiler changes have been integrated and reviewed.
        self.config["sources"] = [self.source]

    def test_candidate_does_not_claim_categories_or_certification(self):
        validate_schema("sources", self.config)
        validate_sources(self.config)
        self.assertEqual(self.source["admission"], "candidate")
        self.assertEqual(self.source["fixture"]["status"], "passed")
        self.assertRegex(self.source["fixture"]["sha256"], r"^[0-9a-f]{64}$")
        report = capability_report(self.config, utc("2026-11-15T13:00:00Z"), ROOT)
        self.assertEqual(report["current_count"], 0)
        self.assertEqual(report["active_count"], 0)
        self.assertEqual(report["dataset_attributions"], [])
        self.assertTrue(all(not row["families"] for row in report["capabilities"]))

    def test_scores_and_counts_cannot_become_reasons_or_usage(self):
        for field in ("ffraud_score", "confirmations"):
            invalid = copy.deepcopy(self.config)
            invalid["sources"][0]["field_mappings"][field] = "reason_flags"
            with self.subTest(field=field), self.assertRaises(ContractError):
                validate_schema("sources", invalid)
        self.assertEqual(self.source["field_mappings"]["type"], "reason_flags")
        self.assertEqual(self.source["parser"], {"id": "ffraud-csv", "schema": "ffraud-five-column-risk-csv-v2", "version": 2})
        for field in ("type", "category"):
            invalid = copy.deepcopy(self.config)
            invalid["sources"][0]["field_mappings"][field] = "usage_type"
            with self.subTest(field=field), self.assertRaises(ContractError):
                validate_schema("sources", invalid)

    def test_new_item_date_column_requires_schema_review(self):
        invalid = copy.deepcopy(self.config)
        invalid["sources"][0]["fields"].append("last_seen")
        with self.assertRaises(ContractError):
            validate_schema("sources", invalid)


if __name__ == "__main__":
    unittest.main()
