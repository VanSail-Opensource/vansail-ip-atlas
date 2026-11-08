import base64
import hashlib
import json
import struct
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.release_contract.contracts import ContractError, make_manifest, parse_canonical, sha256
from tools.release_contract.prepare_static import freeze_csp, scan_frontend, verify_atlas, verify_software_notices, prepare
from tools.release_contract.dataset_credits import write_synthetic_credit_tree


class StaticCandidateTests(unittest.TestCase):
    def atlas(self, root: Path, mode="synthetic", decoded=8):
        # Minimal header/table for inventory and pre-allocation profile fixtures.
        # Actual container integrity is tested separately with the Go inspector.
        data = bytearray(b"VIA3" + bytes(124))
        struct.pack_into("<IQQQ", data, 16, 1, 64, len(data), decoded)
        struct.pack_into("<Q", data, 64 + 24, decoded)
        data = bytes(data)
        digest = sha256(data)
        descriptor = {"format_version": 3, "schema_version": 3, "codec": "zstd-1", "mode": mode,
                      "valid_from": 100, "valid_until": 200,
                      "objects": [{"sha256": digest, "bytes": len(data), "kind": 1, "partition": "all"}]}
        manifest, pointer = make_manifest(descriptor)
        (root / "objects").mkdir()
        (root / "objects" / f"{digest}.via3").write_bytes(data)
        (root / "current.json").write_bytes(pointer)
        release = root / "releases" / parse_canonical(pointer)["release_id"]
        release.mkdir(parents=True)
        (release / "manifest.json").write_bytes(manifest)
        return root / "objects" / f"{digest}.via3"

    def test_exact_atlas_inventory_hash_and_expiry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            object_path = self.atlas(root)
            self.assertEqual(verify_atlas(root, 199)["object_count"], 1)
            with self.assertRaises(ContractError):
                verify_atlas(root, 200)
            object_path.write_bytes(b"X" * 64)
            with self.assertRaises(ContractError):
                verify_atlas(root, 150)

    def test_private_and_orphaned_files_are_rejected(self):
        for extra in ("descriptor.json", "objects/orphan.via3", "source.yaml"):
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.atlas(root)
                (root / extra).write_text("private", encoding="utf-8")
                with self.assertRaises(ContractError):
                    verify_atlas(root, 150)

    def test_production_cannot_be_packaged_through_synthetic_tool(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.atlas(root, "production")
            with self.assertRaises(ContractError):
                verify_atlas(root, 150)

    def test_browser_object_profile_rejects_before_any_decompression(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.atlas(root, decoded=32 * 1024 * 1024 + 1)
            with self.assertRaisesRegex(ContractError, "browser deployment profile"):
                verify_atlas(root, 150)

    def test_csp_hashes_only_exact_executable_inline_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = 'window.__NUXT__={config:{public:{}}};'
            (root / "ip.html").write_text(f'<script>{script}</script><script type="application/json">{{"city":"香港"}}</script>', encoding="utf-8")
            (root / "_headers").write_text("/*\n  Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'\n", encoding="utf-8")
            self.assertEqual(freeze_csp(root), 1)
            encoded = base64.b64encode(hashlib.sha256(script.encode()).digest()).decode()
            self.assertIn(f"'sha256-{encoded}'", (root / "_headers").read_text())
            self.assertEqual(freeze_csp(root), 1)
            self.assertNotIn("unsafe-inline", (root / "_headers").read_text())

    def test_source_maps_and_known_private_literals_block_static_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            file = root / "entry.js"
            file.write_text('const source="private-publisher";', encoding="utf-8")
            with self.assertRaises(ContractError):
                scan_frontend(root, ("private-publisher",))
            file.unlink()
            (root / "entry.js.map").write_text("{}", encoding="utf-8")
            with self.assertRaises(ContractError):
                scan_frontend(root)

    def test_failed_packaging_restores_previous_atlas_and_credit_index_together(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            atlas, public = root / "input", root / "public"
            atlas.mkdir(); public.mkdir()
            self.atlas(atlas, decoded=9)
            previous = public / "_atlas"
            previous.mkdir()
            self.atlas(previous, decoded=8)
            old_pointer = (previous / "current.json").read_bytes()
            old_id = parse_canonical(old_pointer)["release_id"]
            write_synthetic_credit_tree(public, old_id, {old_id: "synthetic"})
            old_index = (public / "dataset-credits.json").read_bytes()
            (public / "_headers").write_text("/*\n  Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'\n", encoding="utf-8")
            (public / "entry.js").write_text('const label="private-publisher";', encoding="utf-8")
            with patch("tools.release_contract.prepare_static.inspect_binary", return_value=1), patch("tools.release_contract.prepare_static.known_private_values", return_value=("private-publisher",)):
                with self.assertRaises(ContractError):
                    prepare(atlas, public, 150)
            self.assertEqual((previous / "current.json").read_bytes(), old_pointer)
            self.assertEqual((public / "dataset-credits.json").read_bytes(), old_index)
            self.assertEqual(list(root.glob("atlas-stage-*")), [])

    def test_software_notice_inventory_detects_postbuild_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            public = Path(directory)
            root = public / "licenses"
            root.mkdir()
            data = b"Exact installed license notice\n"
            (root / "software.txt").write_bytes(data)
            manifest = {"format_version": 1, "scope": "software-distribution-notices",
                        "packages": [{"name": "software.dev", "versions": ["1.0.0"], "license": "MIT"}],
                        "files": [{"path": "software.txt", "bytes": len(data), "sha256": sha256(data)}]}
            (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            verify_software_notices(public)
            # A verified software filename/package identity is not an IP domain fact.
            scan_frontend(public)
            (root / "software.txt").write_bytes(data + b"injected")
            with self.assertRaises(ContractError):
                verify_software_notices(public)


if __name__ == "__main__":
    unittest.main()
