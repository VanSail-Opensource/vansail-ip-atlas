import copy
import tempfile
from pathlib import Path
import unittest

from tools.release_contract.contracts import (
    ContractError, MAX_ASSET_BYTES, MAX_FILES, aggregate_expiry, canonical_bytes,
    eligible, make_manifest, parse_canonical, rollback_eligible, scan_frontend_text,
    scan_public_records, sha256, tree_inventory, validate_descriptor,
    validate_inventory, verify_approval, verify_manifest,
)


def descriptor(mode="synthetic"):
    return {"format_version": 3, "schema_version": 3, "codec": "zstd-1", "mode": mode,
            "valid_from": 1_800_000_000, "valid_until": 1_800_000_100,
            "objects": [{"sha256": "a" * 64, "bytes": 64, "kind": 1, "partition": "all"}]}


class CanonicalTests(unittest.TestCase):
    def test_sorted_utf8_integer_json(self):
        self.assertEqual(canonical_bytes({"z": "香港", "a": 0}), '{"a":0,"z":"香港"}'.encode())

    def test_noncanonical_or_duplicate_rejected(self):
        for sample in (b'{"a":1,"a":2}', b'{ "a":1}', b'{"a":1}\n', b'\xef\xbb\xbf{}',
                       b'{"a":1.0}', b'{"a":NaN}', b'{"a":9007199254740992}', b'{"a":"\\ud800"}'):
            with self.subTest(sample=sample), self.assertRaises(ContractError):
                parse_canonical(sample)

    def test_non_nfc_rejected(self):
        with self.assertRaises(ContractError):
            canonical_bytes({"city": "e\u0301"})


class IdentityTests(unittest.TestCase):
    def test_acyclic_deterministic_identity(self):
        first = make_manifest(descriptor())
        second = make_manifest(dict(reversed(list(descriptor().items()))))
        self.assertEqual(first, second)
        manifest = verify_manifest(*first, now=1_800_000_050)
        self.assertEqual(manifest["release_id"], sha256(canonical_bytes(descriptor())))

    def test_post_preview_tamper_fails(self):
        manifest, pointer = make_manifest(descriptor())
        changed = descriptor()
        changed["objects"][0]["bytes"] += 1
        mutated, _ = make_manifest(changed)
        with self.assertRaises(ContractError):
            verify_manifest(mutated, pointer, 1_800_000_050)

    def test_manifest_path_cannot_be_current_or_traversal(self):
        manifest, pointer = make_manifest(descriptor())
        for path in ("/_atlas/releases/current/manifest.json", "/_atlas/releases/../manifest.json",
                     "https://example.invalid/manifest.json"):
            value = parse_canonical(pointer)
            value["manifest_path"] = path
            with self.subTest(path=path), self.assertRaises(ContractError):
                verify_manifest(manifest, canonical_bytes(value), 1_800_000_050)

    def test_object_and_manifest_schema_fail_closed(self):
        mutations = [lambda d: d.update(source_id="private"),
                     lambda d: d.update(codec="gzip"),
                     lambda d: d.update(valid_until=d["valid_from"]),
                     lambda d: d["objects"][0].update(bytes=MAX_ASSET_BYTES),
                     lambda d: d["objects"][0].update(kind=15),
                     lambda d: d["objects"][0].update(sha256="A" * 64),
                     lambda d: d["objects"].append(copy.deepcopy(d["objects"][0])),
                     lambda d: d["objects"][0].update(partition="source-name")]
        for mutate in mutations:
            value = descriptor()
            mutate(value)
            with self.subTest(value=value), self.assertRaises(ContractError):
                validate_descriptor(value)

    def test_partition_encoding_rejects_host_bits_and_asn_overflow(self):
        for partition in ("4:00000000000000000000000008080801/24", "4:00000000000000000000000000000000/33",
                          "asn:0:100", "asn:100:1", "asn:01:2", "asn:1:4294967295"):
            value = descriptor()
            value["objects"][0]["partition"] = partition
            with self.subTest(partition=partition), self.assertRaises(ContractError):
                validate_descriptor(value)


class ExpiryTests(unittest.TestCase):
    def test_old_item_not_renewed_by_new_snapshot(self):
        self.assertEqual(aggregate_expiry([(1000, 100, True)]), 100 + 168 * 3600)

    def test_source_limit_is_not_build_time_plus_age(self):
        self.assertEqual(aggregate_expiry([(100, None, False), (200, None, False)]), 100 + 720 * 3600)

    def test_exact_expiry_boundary_and_withdrawal(self):
        self.assertTrue(eligible(100, 200, 199))
        self.assertFalse(eligible(100, 200, 200))
        self.assertFalse(eligible(100, 200, 99))
        self.assertFalse(eligible(100, 200, 150, withdrawn=True))

    def test_rollback_cannot_restore_expired_or_withdrawn_data(self):
        self.assertFalse(rollback_eligible(100, 200, 200))
        self.assertFalse(rollback_eligible(100, 200, 150, withdrawn=True))
        self.assertFalse(rollback_eligible(100, 100 + 720 * 3600, 100 + 48 * 3600))

    def test_warm_unchanged_manifest_expires(self):
        manifest, pointer = make_manifest(descriptor())
        verify_manifest(manifest, pointer, 1_800_000_099)
        with self.assertRaises(ContractError):
            verify_manifest(manifest, pointer, 1_800_000_100)

    def test_unknown_clock_cannot_create_release(self):
        for values in ([], [(None, None, True)], [(100, None, True)], [(100, -1, True)], [(100, None, "yes")]):
            with self.subTest(values=values), self.assertRaises(ContractError):
                aggregate_expiry(values)


class InventoryTests(unittest.TestCase):
    def test_pages_limits_are_strict(self):
        digest = "0" * 64
        validate_inventory([("large.bin", MAX_ASSET_BYTES - 1, digest)])
        with self.assertRaises(ContractError):
            validate_inventory([("large.bin", MAX_ASSET_BYTES, digest)])
        with self.assertRaises(ContractError):
            validate_inventory([(f"{n}.bin", 0, digest) for n in range(MAX_FILES)])

    def test_duplicate_unsafe_paths_rejected(self):
        for path in ("../private", "/absolute", "a//b", "a/./b", "a\\b", "a/%2e", "a/.secret", "x:y"):
            with self.subTest(path=path), self.assertRaises(ContractError):
                validate_inventory([(path, 0, "a" * 64)])
        with self.assertRaises(ContractError):
            validate_inventory([("a", 0, "a" * 64), ("a", 1, "b" * 64)])

    def test_entire_candidate_digest_changes_with_frontend_or_control_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "index.html").write_text("hero", encoding="utf-8")
            (root / "_redirects").write_text("/ /ip 302\n", encoding="utf-8")
            entries, before = tree_inventory(root)
            self.assertEqual(len(entries), 2)
            (root / "_redirects").write_text("/ /ip 301\n", encoding="utf-8")
            self.assertNotEqual(before, tree_inventory(root)[1])


class PublicScannerTests(unittest.TestCase):
    def test_real_metadata_rejected(self):
        for value in ({"source_name": "private"}, {"port": 443}, {"geo": {"timezone": "UTC"}},
                      {"evidence_family": "unlisted-private-family"}, {"PublishedAt": 1794096000},
                      {"source_group": "unlisted-private-publisher"},
                      {"as_name": "example.invalid"}, {"as_name": "alice@example.invalid"},
                      {"label": "vmess://secret"}, {"label": "https://tile.openstreetmap.org"}):
            with self.subTest(value=value), self.assertRaises(ContractError):
                scan_public_records(value)

    def test_ordinary_public_facts_are_valid(self):
        scan_public_records({"country": "HK", "city": "香港", "as_name": "Example Network",
                             "asn": 13335, "quality": None, "anycast": False,
                             "coordinates": [2230, 11420]})

    def test_known_private_values_and_escaped_leaks_rejected(self):
        for text in ('const a="private-publisher";', 'const a="private\\u002dpublisher";',
                     'const a="private\\x2dpublisher";', 'const a="cHJpdmF0ZS1wdWJsaXNoZXI=";',
                     'const a="private%2Dpublisher";'):
            with self.subTest(text=text), self.assertRaises(ContractError):
                scan_frontend_text(text, ("private-publisher",))

    def test_library_tokens_and_osm_attribution_do_not_mean_ip_provenance(self):
        scan_frontend_text('const protocol = location.protocol; const domain = window.location.hostname;')
        scan_frontend_text('<a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>')
        scan_frontend_text('img.src="https://tile.openstreetmap.org/1/1/1.png";')

    def test_serialized_forbidden_fields_in_bundle_rejected(self):
        for text in ('const x={"source_url":"secret"}', 'const x={"port":443}',
                     'const x={"credentials":[]}', 'const x={"domain":{}}'):
            with self.subTest(text=text), self.assertRaises(ContractError):
                scan_frontend_text(text)


class ApprovalTests(unittest.TestCase):
    def approval(self, mode="production"):
        manifest, _ = make_manifest(descriptor(mode))
        source, audit, evidence = b"private catalog", b"private rights", b"hosted evidence"
        digest = "b" * 64
        approval = {"public_release_approved": True, "approver": "reviewer",
                    "approved_at": "2026-11-08T00:00:00Z", "source_catalog_sha256": sha256(source),
                    "rights_audit_sha256": sha256(audit), "release_manifest_sha256": sha256(manifest),
                    "release_id": parse_canonical(manifest)["release_id"],
                    "candidate_bundle_sha256": digest, "evidence_sha256": sha256(evidence)}
        return approval, source, audit, manifest, digest, evidence

    def test_exact_hash_binding(self):
        args = self.approval()
        verify_approval(*args)
        for index in (1, 2, 3, 4, 5):
            changed = list(args)
            changed[index] += b"mutated" if isinstance(changed[index], bytes) else "0"
            with self.subTest(index=index), self.assertRaises(ContractError):
                verify_approval(*changed)

    def test_synthetic_cannot_be_approved(self):
        with self.assertRaises(ContractError):
            verify_approval(*self.approval("synthetic"))

    def test_true_requirements_are_not_approval(self):
        args = list(self.approval())
        args[0]["public_release_approved"] = False
        args[0]["requirements"] = {"hosted_regression_passed": True}
        with self.assertRaises(ContractError):
            verify_approval(*args)


if __name__ == "__main__":
    unittest.main()
