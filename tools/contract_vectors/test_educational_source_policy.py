"""The explicit educational decision changes rights policy, not source evidence."""
import copy
import unittest
from unittest.mock import patch

from tools.atlas_contracts.config import ContractError, ROOT, load_yaml, validate_schema, validate_sources
from tools.atlas_contracts.policy import (
    Snapshot, reviewed_distribution_decision, runtime_state, static_issues, utc,
)


EDUCATIONAL = "user_authorized_educational_use"


class EducationalSourcePolicyTests(unittest.TestCase):
    def setUp(self):
        # Loading controls does not certify this fixture or any catalog source.
        self.catalog = load_yaml(ROOT / "configs/sources.yaml")
        self.source = copy.deepcopy(self.catalog["sources"][0])
        self.source["license"].update(distribution=EDUCATIONAL,
            evidence_url="https://publisher.example/terms",
            review_basis="User authorized educational use; recorded publisher terms do not grant redistribution.")

    def issues(self, source=None):
        with patch("tools.atlas_contracts.policy.fixture_issues", side_effect=lambda *args: []):
            return static_issues(source or self.source, ROOT)

    def test_exact_decisions_preserve_reviewed_terms_and_original_defaults(self):
        for decision in ("allow", EDUCATIONAL):
            self.source["license"]["distribution"] = decision
            with self.subTest(decision=decision):
                self.assertTrue(reviewed_distribution_decision(self.source["license"]))
                self.assertEqual(self.issues(), [])
        for decision in ("deny", "review", "unknown", "ALLOW", "educational", EDUCATIONAL + " ", None, True, {}):
            self.source["license"]["distribution"] = decision
            with self.subTest(decision=decision):
                self.assertFalse(reviewed_distribution_decision(self.source["license"]))
                self.assertIn("reviewed_redistribution_rights_required", self.issues())

    def test_educational_use_requires_explicit_safe_review_evidence(self):
        mutations = [
            ("status", "needs-review"), ("status", "restricted"),
            ("review_basis", ""), ("review_basis", " \t\n"), ("review_basis", None),
            ("evidence_url", None), ("evidence_url", "http://publisher.example/terms"),
            ("evidence_url", "https://127.0.0.1/terms"),
            ("evidence_url", "https://secret@publisher.example/terms"),
            ("evidence_url", "https://publisher.example/terms?secret=1"),
        ]
        for key, value in mutations:
            source = copy.deepcopy(self.source)
            source["license"][key] = value
            with self.subTest(key=key, value=value):
                self.assertIn("reviewed_redistribution_rights_required", self.issues(source))
        for key in ("review_basis", "evidence_url"):
            source = copy.deepcopy(self.source)
            del source["license"][key]
            self.assertIn("reviewed_redistribution_rights_required", self.issues(source))

    def test_educational_use_keeps_attribution_fixture_and_publication_gates(self):
        for value in (None, "false", 0):
            source = copy.deepcopy(self.source)
            source["license"]["attribution_required"] = value
            self.assertIn("explicit_attribution_requirement_required", self.issues(source))
        self.source["license"]["attribution_required"] = True
        self.source["license"].pop("attribution", None)
        self.assertIn("reviewed_dataset_attribution_required", self.issues())
        self.source["license"]["attribution"] = {
            "name": "Synthetic Publisher", "text": "Recorded upstream notice",
            "url": "https://publisher.example/terms",
        }
        self.assertEqual(self.issues(), [])
        self.source["license"]["attribution"]["url"] = "https://127.0.0.1/terms"
        self.assertIn("reviewed_dataset_attribution_required", self.issues())
        with patch("tools.atlas_contracts.policy.fixture_issues", return_value=["reviewed_adapter_certification_required"]):
            self.assertIn("reviewed_adapter_certification_required", static_issues(self.source, ROOT))
        self.source["publication_proof"]["kind"] = "unavailable"
        self.assertIn("payload_publication_proof_required", self.issues())

    def test_runtime_rechecks_decision_and_freshness_for_identical_payload(self):
        now = utc("2026-11-15T00:00:00Z")
        snapshot = Snapshot("a" * 64, "a" * 64, self.source["publication_proof"]["kind"],
                            "2026-11-14T00:00:00Z", True, True, True)
        with patch("tools.atlas_contracts.policy.fixture_issues", side_effect=lambda *args: []):
            self.assertEqual(runtime_state(self.source, snapshot, now, ROOT), ("current", []))
            self.source["license"]["distribution"] = "deny"
            self.assertEqual(runtime_state(self.source, snapshot, now, ROOT)[0], "quarantined")
            self.source["license"]["distribution"] = EDUCATIONAL
            old = Snapshot("a" * 64, "a" * 64, snapshot.proof_kind,
                           "2026-10-01T00:00:00Z", True, True, True)
            self.assertEqual(runtime_state(self.source, old, now, ROOT), ("stale", ["publication_expired"]))

    def test_closed_schema_and_rights_milestone_require_explicit_decision(self):
        for source in self.catalog["sources"]:
            source["admission"] = "candidate"
        self.catalog["sources"][0] = self.source
        self.source["admission"] = "rights_approved"
        validate_schema("sources", self.catalog)
        validate_sources(self.catalog)
        for key, value in (("distribution", "educational"), ("review_basis", " \t"),
                           ("evidence_url", None), ("attribution_required", None)):
            bad = copy.deepcopy(self.catalog)
            bad["sources"][0]["license"][key] = value
            with self.subTest(key=key), self.assertRaises(ContractError):
                validate_schema("sources", bad)
            with self.subTest(key=key), self.assertRaises(ContractError):
                validate_sources(bad)

    def test_global_policy_stays_closed_and_mandatory(self):
        validate_schema("sources", self.catalog)
        for path, current, previous in (
            (("build", "storage"), "publish_only_reviewed_distribution_decisions", "publish_only_license_allow"),
            (("build", "source_policy"), "active_requires_reviewed_distribution_decision", "active_requires_public_redistribution"),
            (("source_defaults",), "requires_reviewed_distribution_decision", "requires_redistribution_approval"),
        ):
            for legacy in (False, True):
                bad = copy.deepcopy(self.catalog)
                target = bad
                for key in path:
                    target = target[key]
                if legacy:
                    target[previous] = target.pop(current)
                else:
                    target[current] = False
                with self.subTest(field=current, legacy=legacy), self.assertRaises(ContractError):
                    validate_schema("sources", bad)


if __name__ == "__main__":
    unittest.main()
