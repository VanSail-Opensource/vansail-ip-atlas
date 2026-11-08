import copy
from dataclasses import replace
from datetime import timedelta
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest
import subprocess
import sys

from tools.atlas_contracts.config import ContractError, ROOT, load_configs, load_yaml, validate_schema, validate_sources
from tools.atlas_contracts.policy import Snapshot, adapter_code_hash, capability_report, fixture_issues, runtime_state, static_issues, utc


class ConfigurationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.configs = load_configs()

    def test_actual_catalog_is_blocked_and_has_shared_family(self):
        report = capability_report(self.configs["sources"], utc("2026-11-08T00:00:00Z"), ROOT)
        self.assertEqual((report["source_count"], report["active_count"], report["current_count"]), (91, 0, 0))
        self.assertFalse(report["production_eligible"])
        self.assertEqual(report["schema_version"], 2)
        self.assertEqual(report["release_scope"], "release-scope-v2")
        self.assertEqual(len(report["capabilities"]), 13)
        required = [row for row in report["capabilities"] if row["required"]]
        optional = [row for row in report["capabilities"] if not row["required"]]
        self.assertEqual(len(required), 12)
        self.assertTrue(all(row["status"] == "blocked" for row in required))
        self.assertEqual([(row["capability"], row["status"]) for row in optional], [("numeric_quality", "unrated")])
        self.assertEqual(report["required_capability_count"], 12)
        self.assertEqual(report["blocked_required_capability_count"], 12)
        subscriptions = [s for s in self.configs["sources"]["sources"] if s["category"] == "proxy_subscription_ip"]
        self.assertEqual(len(subscriptions), 21)
        self.assertEqual({s["evidence_family"] for s in subscriptions}, {"public-subscription-aggregators"})

    def test_cli_counts_only_required_capabilities_and_preserves_other_release_blocks(self):
        result = subprocess.run([sys.executable, str(ROOT / "tools/validate_blueprint.py"), "--now", "2026-11-08T00:00:00Z", "--require-production"],
                                cwd=ROOT, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("12/12 required capabilities", result.stdout)
        self.assertIn("Optional numeric quality: unrated", result.stdout)
        production_line = next(line for line in result.stdout.splitlines() if line.startswith("Production BLOCKED"))
        self.assertNotIn("numeric_quality", production_line)
        self.assertIn("pages_release", production_line)

    def test_unknown_keys_rejected_in_every_config(self):
        for name, value in self.configs.items():
            invalid = copy.deepcopy(value)
            invalid["unexpected"] = True
            with self.subTest(name=name), self.assertRaises(ContractError):
                validate_schema(name, invalid)

    def test_unknown_nested_source_keys_and_obsolete_enabled_rejected(self):
        for path in [("enabled",), ("fixture", "extra"), ("parser", "extra"), ("license", "extra")]:
            invalid = copy.deepcopy(self.configs["sources"])
            target = invalid["sources"][0]
            for part in path[:-1]:
                target = target[part]
            target[path[-1]] = True
            with self.subTest(path=path), self.assertRaises(ContractError):
                validate_schema("sources", invalid)

    def test_duplicate_keys_aliases_and_yaml_bombs_rejected(self):
        for content in ["a: 1\na: 2\n", "a: &x [1]\nb: *x\n", "a: " + "[" * 40 + "0" + "]" * 40, "!!python/object:danger {}"]:
            with tempfile.TemporaryDirectory() as temp:
                path = Path(temp) / "bad.yaml"
                path.write_text(content, encoding="utf-8")
                with self.subTest(content=content[:20]), self.assertRaises(ContractError):
                    load_yaml(path)

    def test_duplicate_ids_cycle_and_missing_dependency_rejected(self):
        for kind in ("duplicate", "cycle", "missing"):
            invalid = copy.deepcopy(self.configs["sources"])
            sources = invalid["sources"]
            if kind == "duplicate":
                sources[1]["id"] = sources[0]["id"]
            elif kind == "cycle":
                sources[0]["depends_on"] = [sources[1]["id"]]
                sources[1]["depends_on"] = [sources[0]["id"]]
            else:
                sources[0]["depends_on"] = ["missing"]
            with self.subTest(kind=kind), self.assertRaises(ContractError):
                validate_sources(invalid)

    def test_scope_alias_enum_and_hash_rejected(self):
        for field, value in [("scope", "exact-ip"), ("category", "guessed"), ("admission", "enabled")]:
            invalid = copy.deepcopy(self.configs["sources"])
            invalid["sources"][0][field] = value
            with self.subTest(field=field), self.assertRaises(ContractError):
                validate_schema("sources", invalid)
        invalid = copy.deepcopy(self.configs["sources"])
        invalid["sources"][0]["fixture"]["sha256"] = "not-a-hash"
        with self.assertRaises(ContractError):
            validate_schema("sources", invalid)

    def test_wrong_types_and_nonfinite_weights_rejected(self):
        for weight in (True, "70", -1, 101, float("nan"), float("inf")):
            invalid = copy.deepcopy(self.configs["sources"])
            invalid["sources"][0]["trust"]["source_weight"] = weight
            with self.subTest(weight=str(weight)), self.assertRaises(ContractError):
                validate_schema("sources", invalid)

    def test_active_cannot_bypass_missing_certification(self):
        for status in ("active", "fixture_tested"):
            invalid = copy.deepcopy(self.configs["sources"])
            invalid["sources"][0]["admission"] = status
            with self.subTest(status=status), self.assertRaises(ContractError):
                validate_sources(invalid)

    def test_unreviewed_policy_change_rejected(self):
        invalid = copy.deepcopy(self.configs["scoring"])
        invalid["layers"]["weights"]["asn"] = 0.2
        with self.assertRaises(ContractError):
            validate_schema("scoring", invalid)

    def test_forbidden_raw_label_cannot_be_mapped_to_public_isp(self):
        invalid = copy.deepcopy(self.configs["sources"])
        source = invalid["sources"][0]
        source["fields"].append("organization_domain")
        source["public_fields"] = ["isp"]
        source["field_mappings"] = {"organization_domain": "isp"}
        with self.assertRaises(ContractError):
            validate_sources(invalid)


class AdmissionClockTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        fixture = self.root / "fixtures/source-certification/minimal.txt"
        fixture.parent.mkdir(parents=True)
        fixture.write_bytes(b"observed payload shape\n")
        # Test-only source; never added to the real catalog or a production report.
        source = copy.deepcopy(load_configs()["sources"]["sources"][0])
        source["admission"] = "active"
        source["parser"] = {"id": "test-range", "schema": "test-v1", "version": 1}
        source["fixture"] = {"status": "passed", "sha256": sha256(fixture.read_bytes()).hexdigest(),
                             "schema_observed": True, "tested_at": "2026-11-08T00:00:00Z",
                             "path": "fixtures/source-certification/minimal.txt", "parser": "test-range",
                             "schema": "test-v1", "synthetic": False}
        source["license"].update(attribution_required=False)
        source["public_fields"] = ["physical_country"]
        source["field_mappings"] = {"country_code": "physical_country"}
        (self.root / "internal").mkdir()
        (self.root / "internal/test.go").write_text("package contracttest\n", encoding="utf-8")
        ledger = {"schema_version": 1, "certifications": [{"source_id": source["id"], "parser": "test-range", "schema": "test-v1", "version": 1,
            "fixture_sha256": source["fixture"]["sha256"], "tested_at": source["fixture"]["tested_at"], "implementation_sha256": adapter_code_hash(self.root)}]}
        (self.root / "fixtures/source-certification/adapter-certifications.json").write_text(json.dumps(ledger), encoding="utf-8")
        self.source = source
        self.now = utc("2026-11-08T00:00:00Z")
        self.snapshot = Snapshot("a" * 64, "a" * 64, "github_release", "2026-11-08T00:00:00Z", True, True)
        self.assertEqual(static_issues(source, self.root), [])

    def state(self, snapshot=None, now=None):
        return runtime_state(self.source, snapshot or self.snapshot, now or self.now, self.root)[0]

    def test_publication_expiry_boundary_and_future_tolerance(self):
        self.assertEqual(self.state(), "current")
        self.assertEqual(self.state(now=self.now + timedelta(hours=720) - timedelta(microseconds=1)), "current")
        self.assertEqual(self.state(now=self.now + timedelta(hours=720)), "stale")
        self.assertEqual(self.state(replace(self.snapshot, published_at="2026-11-09T00:00:00Z")), "current")
        self.assertEqual(self.state(replace(self.snapshot, published_at="2026-11-09T00:00:01Z")), "quarantined")

    def test_payload_binding_schema_and_publication_proof(self):
        for snapshot, expected in [(replace(self.snapshot, proof_payload_sha256="b" * 64), "quarantined"),
                                   (replace(self.snapshot, published_at=""), "quarantined"),
                                   (replace(self.snapshot, schema_verified=False), "invalid"),
                                   (replace(self.snapshot, integrity_verified=False), "invalid")]:
            with self.subTest(expected=expected):
                self.assertEqual(self.state(snapshot), expected)

    def test_cache_fetch_and_304_cannot_extend_unchanged_age(self):
        old = replace(self.snapshot, published_at="2026-10-01T00:00:00Z")
        for _ in range(3):
            self.assertEqual(self.state(old), "stale")
        self.assertNotIn("fetched_at", Snapshot.__dataclass_fields__)
        self.assertNotIn("http_status", Snapshot.__dataclass_fields__)

    def test_github_commit_requires_exact_payload_binding(self):
        self.source["publication_proof"]["kind"] = "github_commit"
        mutable = replace(self.snapshot, proof_kind="github_commit")
        self.assertEqual(self.state(mutable), "quarantined")
        self.assertEqual(self.state(replace(mutable, immutable_commit_bound=True)), "current")

    def test_subscription_stricter_item_and_payload_clock(self):
        self.source["category"] = "proxy_subscription_ip"
        self.assertEqual(self.state(), "quarantined")
        self.snapshot = replace(self.snapshot, item_published_at="2026-11-08T00:00:00Z")
        self.assertEqual(self.state(now=self.now + timedelta(hours=168)), "stale")
        item = replace(self.snapshot, item_published_at="2026-10-31T00:00:00Z")
        self.assertEqual(self.state(item), "stale")

    def test_untrusted_headers_not_allowlisted(self):
        self.source["publication_proof"]["kind"] = "authoritative_header"
        self.assertEqual(self.state(replace(self.snapshot, proof_kind="authoritative_header")), "quarantined")

    def test_rights_withdrawal_and_synthetic_fixture_retract(self):
        self.source["license"]["attribution_required"] = True
        self.assertEqual(self.state(), "quarantined")
        self.source["license"]["attribution_required"] = False
        self.source["fixture"]["synthetic"] = True
        self.assertEqual(self.state(), "quarantined")

    def test_fixture_bytes_hash_and_controlled_path(self):
        self.source["fixture"]["sha256"] = "b" * 64
        self.assertIn("fixture_hash_mismatch", fixture_issues(self.source, self.root))
        self.source["fixture"]["path"] = "../../outside"
        self.assertIn("controlled_fixture_path_required", fixture_issues(self.source, self.root))

    def test_missing_payload_and_retirement(self):
        self.assertEqual(runtime_state(self.source, None, self.now, self.root)[0], "missing")
        self.source["admission"] = "retired"
        self.assertEqual(self.state(), "quarantined")

    def test_labels_and_changed_code_cannot_bypass_adapter_certification(self):
        self.source["parser"]["id"] = "guessed-parser"
        self.source["fixture"]["parser"] = "guessed-parser"
        self.assertEqual(self.state(), "quarantined")
        self.source["parser"]["id"] = "test-range"
        self.source["fixture"]["parser"] = "test-range"
        self.assertEqual(self.state(), "current")
        (self.root / "internal/test.go").write_text("package changed\n", encoding="utf-8")
        self.assertEqual(self.state(), "quarantined")


if __name__ == "__main__":
    unittest.main()
