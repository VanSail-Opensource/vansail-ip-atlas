import json
from pathlib import Path
import tempfile
import unittest

from tools.release_contract.contracts import ContractError, canonical_bytes, make_manifest, parse_canonical, sha256
from tools.release_contract.production import qualify


class ProductionQualificationTests(unittest.TestCase):
    def fixture(self, root, *, attributed=True, distribution="allow"):
        (root / "configs").mkdir()
        credit = {"name": "Example mapping", "text": "Example mapping contributors", "url": "https://example.org/"}
        rights = {"status": "reviewed", "distribution": distribution, "attribution_required": attributed,
                  "evidence_url": "https://example.org/license", "review_basis": "observed license"}
        if attributed:
            rights["attribution"] = credit
        source = {"id": "example", "admission": "active", "license": rights,
                  "parser": {"id": "example-v1", "schema": "example-map-v1", "version": 1},
                  "evidence_family": "example-publisher"}
        catalog = {"sources": [source]}
        (root / "configs/sources.yaml").write_text(json.dumps(catalog), encoding="utf-8")
        (root / "SOURCES_AUDIT.md").write_text("Fixture rights decision", encoding="utf-8")
        descriptor = {"format_version": 3, "schema_version": 5, "codec": "zstd-1", "mode": "production",
            "valid_from": 100, "valid_until": 200,
            "objects": [{"sha256": "a" * 64, "bytes": 128, "kind": 1, "partition": "all"}]}
        manifest, _ = make_manifest(descriptor)
        release_id = parse_canonical(manifest)["release_id"]
        atlas = root / "atlas"
        directory = atlas / "releases" / release_id
        directory.mkdir(parents=True)
        (directory / "manifest.json").write_bytes(manifest)
        record = {"schema_version": 1, "release_scope": "release-scope-v6", "mode": "production",
            "evaluated_at": 100, "valid_until": 200, "release_id": release_id,
            "release_manifest_sha256": sha256(manifest),
            "source_catalog_sha256": sha256((root / "configs/sources.yaml").read_bytes()),
            "rights_audit_sha256": sha256((root / "SOURCES_AUDIT.md").read_bytes()),
            **{key: "b" * 64 for key in ("normalization_config_sha256", "implementation_sha256",
                "certification_sha256", "normalized_state_sha256", "source_capabilities_sha256")},
            "included_sources": [{"source_id": "example", "payload_sha256": "c" * 64,
                "proof_sha256": "c" * 64, "published_at": 90, "expires_at": 220,
                "parser": "example-v1", "schema": "example-map-v1", "parser_version": 1,
                "evidence_family": "example-publisher", "rights_sha256": sha256(canonical_bytes(rights)),
                "attribution_sha256": sha256(canonical_bytes(credit)) if attributed else None}]}
        path = root / "receipt.json"
        path.write_bytes(canonical_bytes(record))
        return atlas, path, record, credit

    def test_credits_come_only_from_included_reviewed_sources_and_store_is_reopened(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            atlas, path, record, credit = self.fixture(root)
            calls = []
            result = qualify(path, atlas, 150, workspace=root, verifier=lambda *args: calls.append(args))
            self.assertEqual(result.credits, (credit,))
            self.assertEqual(result.receipt_sha256, sha256(path.read_bytes()))
            self.assertEqual(calls, [(root, path, atlas, 150)])
            self.assertEqual(result.release_id, record["release_id"])

    def test_receipt_does_not_substitute_for_actual_store_verification(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            atlas, path, _, _ = self.fixture(root)
            def deny(*args):
                raise ContractError("sealed source state changed")
            with self.assertRaisesRegex(ContractError, "sealed source state changed"):
                qualify(path, atlas, 150, workspace=root, verifier=deny)

    def test_missing_extra_forged_or_expired_bindings_fail_before_verifier(self):
        mutations = {
            "success_boolean": lambda r: r.update(production_eligible=True),
            "synthetic": lambda r: r.update(mode="synthetic"),
            "scope": lambda r: r.update(release_scope="release-scope-v2"),
            "old_full_scope": lambda r: r.update(release_scope="release-scope-v5"),
            "empty_inclusion": lambda r: r.update(included_sources=[]),
            "expiry": lambda r: r.update(valid_until=150),
            "future": lambda r: r.update(evaluated_at=151),
            "wrong_manifest": lambda r: r.update(release_manifest_sha256="0" * 64),
            "wrong_catalog": lambda r: r.update(source_catalog_sha256="0" * 64),
            "wrong_rights": lambda r: r["included_sources"][0].update(rights_sha256="0" * 64),
            "missing_credit": lambda r: r["included_sources"][0].update(attribution_sha256=None),
            "unknown_source": lambda r: r["included_sources"][0].update(source_id="unused"),
            "duplicate_source": lambda r: r["included_sources"].append(dict(r["included_sources"][0])),
            "source_expiry": lambda r: r["included_sources"][0].update(expires_at=199),
            "bool_parser_version": lambda r: r["included_sources"][0].update(parser_version=True),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                atlas, path, record, _ = self.fixture(root)
                mutate(record)
                path.write_bytes(canonical_bytes(record))
                calls = []
                with self.assertRaises(ContractError):
                    qualify(path, atlas, 150, workspace=root, verifier=lambda *args: calls.append(args))
                self.assertEqual(calls, [])

    def test_optional_credit_is_not_fabricated(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            atlas, path, _, _ = self.fixture(root, attributed=False)
            result = qualify(path, atlas, 150, workspace=root, verifier=lambda *args: None)
            self.assertEqual(result.credits, ())

    def test_catalog_withdrawal_invalidates_exact_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            atlas, path, record, _ = self.fixture(root)
            catalog_path = root / "configs/sources.yaml"
            catalog = json.loads(catalog_path.read_text())
            catalog["sources"][0]["admission"] = "retired"
            catalog_path.write_text(json.dumps(catalog), encoding="utf-8")
            # Even recomputing a catalog digest cannot manufacture active inclusion.
            record["source_catalog_sha256"] = sha256(catalog_path.read_bytes())
            path.write_bytes(canonical_bytes(record))
            with self.assertRaises(ContractError):
                qualify(path, atlas, 150, workspace=root, verifier=lambda *args: None)

    def test_educational_decision_binds_rights_and_reopens_current_store(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            atlas, path, record, credit = self.fixture(root, distribution="user_authorized_educational_use")
            calls = []
            result = qualify(path, atlas, 150, workspace=root, verifier=lambda *args: calls.append(args))
            self.assertEqual(result.credits, (credit,))
            self.assertEqual(calls, [(root, path, atlas, 150)])
            catalog_path = root / "configs/sources.yaml"
            catalog = json.loads(catalog_path.read_text())
            catalog["sources"][0]["license"]["distribution"] = "allow"
            catalog_path.write_text(json.dumps(catalog), encoding="utf-8")
            record["source_catalog_sha256"] = sha256(catalog_path.read_bytes())
            # A valid alternative decision still needs a newly bound receipt.
            path.write_bytes(canonical_bytes(record))
            with self.assertRaises(ContractError):
                qualify(path, atlas, 150, workspace=root, verifier=lambda *args: None)

    def test_fully_rehashed_educational_receipt_cannot_skip_review_or_credit_gates(self):
        mutations = {
            "deny": lambda r: r.update(distribution="deny"),
            "unknown": lambda r: r.update(distribution="educational"),
            "unreviewed": lambda r: r.update(status="needs-review"),
            "empty_basis": lambda r: r.update(review_basis=" \t\n"),
            "missing_terms": lambda r: r.pop("evidence_url"),
            "private_terms": lambda r: r.update(evidence_url="https://127.0.0.1/terms"),
            "missing_attribution_decision": lambda r: r.update(attribution_required=None),
            "missing_credit": lambda r: r.pop("attribution"),
            "changed_credit": lambda r: r["attribution"].update(text="Changed upstream notice"),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                atlas, path, record, _ = self.fixture(root, distribution="user_authorized_educational_use")
                catalog_path = root / "configs/sources.yaml"
                catalog = json.loads(catalog_path.read_text())
                rights = catalog["sources"][0]["license"]
                mutate(rights)
                catalog_path.write_text(json.dumps(catalog), encoding="utf-8")
                record["source_catalog_sha256"] = sha256(catalog_path.read_bytes())
                record["included_sources"][0]["rights_sha256"] = sha256(canonical_bytes(rights))
                path.write_bytes(canonical_bytes(record))
                calls = []
                with self.assertRaises(ContractError):
                    qualify(path, atlas, 150, workspace=root, verifier=lambda *args: calls.append(args))
                self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
