import copy
import json
from pathlib import Path
import tempfile
import unittest

from tools.release_contract.contracts import ContractError, canonical_bytes, parse_canonical, sha256
from tools.release_contract.dataset_credits import (
    build_credit_document,
    validate_credit_tree,
    write_synthetic_credit_tree,
)


CURRENT = "a" * 64
PREVIOUS = "b" * 64
CREDIT = {"name": "Reviewed Dataset", "text": "Data copyright Reviewed Publisher",
          "url": "https://publisher.example/data", "license_url": "https://publisher.example/license"}


class DatasetCreditTests(unittest.TestCase):
    def production(self, root, entries=None):
        data = build_credit_document(CURRENT, "production", [CREDIT] if entries is None else entries)
        digest = sha256(data)
        path = f"_atlas/credits/{digest}.json"
        (root / path).parent.mkdir(parents=True)
        (root / path).write_bytes(data)
        index = {"format_version": 1, "current_release_id": CURRENT, "releases": [{
            "release_id": CURRENT, "credits_path": "/" + path, "credits_sha256": digest}]}
        (root / "dataset-credits.json").write_bytes(canonical_bytes(index))
        return path, index

    def test_production_document_has_only_reviewed_shaped_entries(self):
        document = parse_canonical(build_credit_document(CURRENT, "production", [CREDIT, CREDIT]))
        self.assertEqual(document, {"format_version": 1, "release_id": CURRENT,
                                   "mode": "production", "entries": [CREDIT]})
        changed = dict(CREDIT, text="Updated required credit")
        self.assertNotEqual(sha256(build_credit_document(CURRENT, "production", [CREDIT])),
                            sha256(build_credit_document(CURRENT, "production", [changed])))
        self.assertEqual(build_credit_document(CURRENT, "production", [changed, CREDIT]),
                         build_credit_document(CURRENT, "production", [CREDIT, changed]))

    def test_synthetic_document_cannot_claim_real_dataset_inclusion(self):
        with self.assertRaises(ContractError):
            build_credit_document(CURRENT, "synthetic", [CREDIT])
        self.assertEqual(parse_canonical(build_credit_document(CURRENT, "synthetic", []))["entries"], [])

    def test_entry_keys_text_and_url_injection_fail_closed(self):
        bad = [dict(CREDIT, source_id="private-source"), dict(CREDIT, provenance="private"),
               dict(CREDIT, name=""), dict(CREDIT, text="line\nscript"),
               dict(CREDIT, text="hidden\u202etext"), dict(CREDIT, name="e\u0301"),
               dict(CREDIT, text="\ud800"), dict(CREDIT, license_url=""),
               dict(CREDIT, name="x" * 129), dict(CREDIT, text="x" * 2049)]
        for url in ["javascript:alert(1)", "http://publisher.example/", "https://user:secret@publisher.example/",
                    "https://localhost/", "https://a.local/", "https://a.internal/", "https://127.0.0.1/",
                    "https://10.0.0.1/", "https://100.64.0.1/", "https://[::1]/", "https://[2001:db8::1]/",
                    "https://publisher.example/?q=1", "https://publisher.example/#x", "https://publisher.example:/",
                    "https://publisher.example:8443/", "https://publisher.example:0443/", "https://publisher.example/%zz", "https://publisher.example/<x>",
                    "https://publisher.example/'x'", "https://publisher.example/\"x\"", "https://publisher.example/\\x"]:
            bad.append(dict(CREDIT, url=url))
        for item in bad:
            with self.subTest(item=repr(item)), self.assertRaises(ContractError):
                build_credit_document(CURRENT, "production", [item])

    def test_plain_text_is_data_and_safe_public_https_literals_are_allowed(self):
        # Rendering must escape this literal text; it is never trusted HTML.
        item = dict(CREDIT, text="Copyright <Reviewed Publisher> & contributors", url="https://8.8.8.8/legal%20notice")
        self.assertEqual(parse_canonical(build_credit_document(CURRENT, "production", [item]))["entries"], [item])
        item["url"] = "https://[2606:4700:4700::1111]/license"
        build_credit_document(CURRENT, "production", [item])

    def test_shared_source_admission_url_corpus_matches_public_artifact_boundary(self):
        fixture = Path(__file__).resolve().parents[2] / "fixtures/contracts/attribution-urls-v1.json"
        for item in json.loads(fixture.read_text(encoding="utf-8"))["cases"]:
            with self.subTest(url=item["url"]):
                if item["valid"]:
                    build_credit_document(CURRENT, "production", [dict(CREDIT, url=item["url"])])
                else:
                    with self.assertRaises(ContractError):
                        build_credit_document(CURRENT, "production", [dict(CREDIT, url=item["url"])])

    def test_credits_cannot_carry_subscription_material_or_secret_tokens(self):
        for secret in ("vless://credential@8.8.8.8:443", "SS://secret", "hysteria://credential",
                       "-----BEGIN OPENSSH PRIVATE KEY-----", "ghp_example", "gHo_example", "github_pat_example"):
            for field in ("name", "text", "url", "license_url"):
                value = "https://publisher.example/" + secret if field in ("url", "license_url") else secret
                with self.subTest(field=field, value=value), self.assertRaises(ContractError):
                    build_credit_document(CURRENT, "production", [dict(CREDIT, **{field: value})])

    def test_metadata_and_document_populations_are_bounded(self):
        with self.assertRaises(ContractError):
            build_credit_document(CURRENT, "production", [CREDIT] * 257)
        entries = [dict(CREDIT, name=f"Dataset {i}", text="\U00020000" * 2048) for i in range(256)]
        with self.assertRaises(ContractError):
            build_credit_document(CURRENT, "production", entries)

    def test_synthetic_tree_is_exact_deterministic_and_retains_two_releases(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            modes = {PREVIOUS: "synthetic", CURRENT: "synthetic"}
            paths = write_synthetic_credit_tree(root, CURRENT, modes)
            self.assertEqual(validate_credit_tree(root, CURRENT, modes), paths)
            self.assertEqual(len(paths), 3)
            first = {p: (root / p).read_bytes() for p in paths}
            self.assertEqual(write_synthetic_credit_tree(root, CURRENT, dict(reversed(list(modes.items())))), paths)
            self.assertEqual(first, {p: (root / p).read_bytes() for p in paths})
            with self.assertRaises(ContractError):
                write_synthetic_credit_tree(root, CURRENT, {CURRENT: "production"})

    def test_production_tree_shape_integrity_and_exact_scanner_exception_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, _ = self.production(root)
            self.assertEqual(validate_credit_tree(root, CURRENT, {CURRENT: "production"}),
                             {"dataset-credits.json", path})

    def test_synthetic_writer_cannot_overwrite_conflicting_immutable_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            modes = {CURRENT: "synthetic"}
            paths = write_synthetic_credit_tree(root, CURRENT, modes)
            immutable = next(path for path in paths if path != "dataset-credits.json")
            (root / immutable).write_bytes(b"corrupt immutable evidence")
            before = (root / "dataset-credits.json").read_bytes()
            with self.assertRaises(ContractError):
                write_synthetic_credit_tree(root, CURRENT, modes)
            self.assertEqual((root / immutable).read_bytes(), b"corrupt immutable evidence")
            self.assertEqual((root / "dataset-credits.json").read_bytes(), before)

    def test_missing_hash_mismatch_orphan_and_extra_directory_are_rejected(self):
        for mutation in ("missing", "hash", "orphan", "directory"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                path, _ = self.production(root)
                if mutation == "missing":
                    (root / path).unlink()
                elif mutation == "hash":
                    (root / path).write_bytes(b"{}")
                elif mutation == "orphan":
                    (root / "_atlas/credits" / ("c" * 64 + ".json")).write_bytes(b"{}")
                else:
                    (root / "_atlas/credits/hidden").mkdir()
                with self.assertRaises(ContractError):
                    validate_credit_tree(root, CURRENT, {CURRENT: "production"})

    def test_index_identity_path_keys_and_canonical_bytes_are_rejected(self):
        for mutation in ("release", "mode", "current", "path", "duplicate", "extra", "version_bool", "pretty"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                path, index = self.production(root)
                modes = {CURRENT: "production"}
                if mutation == "release":
                    modes = {PREVIOUS: "production"}
                elif mutation == "mode":
                    modes = {CURRENT: "synthetic"}
                elif mutation == "current":
                    index["current_release_id"] = PREVIOUS
                elif mutation == "path":
                    index["releases"][0]["credits_path"] = "/_atlas/credits/../private.json"
                elif mutation == "duplicate":
                    index["releases"].append(copy.deepcopy(index["releases"][0]))
                elif mutation == "extra":
                    index["source_id"] = "private-source"
                elif mutation == "version_bool":
                    index["format_version"] = True
                (root / "dataset-credits.json").write_bytes(canonical_bytes(index) + (b"\n" if mutation == "pretty" else b""))
                with self.assertRaises(ContractError):
                    validate_credit_tree(root, CURRENT, modes)

    def test_hashed_document_still_requires_closed_canonical_validated_content(self):
        for change in ("source_id", "mode", "duplicate_entries", "noncanonical", "too_large"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                path, index = self.production(root)
                document = parse_canonical((root / path).read_bytes())
                if change == "source_id":
                    document["entries"][0]["source_id"] = "private-source"
                elif change == "mode":
                    document["mode"] = "synthetic"
                elif change == "duplicate_entries":
                    document["entries"] *= 2
                data = canonical_bytes(document)
                if change == "noncanonical":
                    data += b"\n"
                elif change == "too_large":
                    data = b" " * (1024 * 1024 + 1)
                (root / path).unlink()
                digest = sha256(data)
                new_path = f"_atlas/credits/{digest}.json"
                (root / new_path).write_bytes(data)
                index["releases"][0].update(credits_path="/" + new_path, credits_sha256=digest)
                (root / "dataset-credits.json").write_bytes(canonical_bytes(index))
                with self.assertRaises(ContractError):
                    validate_credit_tree(root, CURRENT, {CURRENT: "production"})

    def test_symlink_in_any_credit_path_is_rejected(self):
        for target in ("index", "document", "directory"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / "public"
                root.mkdir()
                path, _ = self.production(root)
                original = root / ("dataset-credits.json" if target == "index" else "_atlas/credits" if target == "directory" else path)
                outside = Path(directory) / "outside"
                original.rename(outside)
                try:
                    original.symlink_to(outside, target_is_directory=target == "directory")
                except OSError:
                    self.skipTest("host cannot create symlinks")
                with self.assertRaises(ContractError):
                    validate_credit_tree(root, CURRENT, {CURRENT: "production"})


if __name__ == "__main__":
    unittest.main()
