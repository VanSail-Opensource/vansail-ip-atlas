import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.release_contract.software_licenses import DIRECT, generate, review_bundle


class SoftwareBundleReviewTests(unittest.TestCase):
    def fixture(self, root: Path):
        public = root / "web/.output/public"
        public.mkdir(parents=True)
        (public / "entry.js").write_bytes(b"export{}")
        metadata = root / "metadata.json"
        records = []
        for name in [*DIRECT, "missing-runtime"]:
            path = root / "web/node_modules" / name
            path.mkdir(parents=True)
            if name in DIRECT:
                (path / "LICENSE").write_text("Exact synthetic software notice\n", encoding="utf-8")
            records.append({"name": name, "versions": ["1.2.3"], "license": "MIT", "paths": [str(path)]})
        metadata.write_text(json.dumps({"MIT": records}), encoding="utf-8")
        asset = {"path": "entry.js", "bytes": 8, "sha256": hashlib.sha256(b"export{}").hexdigest()}
        audit = {"format_version": 1, "scope": "exact-client-and-worker-module-ancestry",
                 "client": {"modules": [], "assets": [asset]}, "workers": []}
        path = root / "audit.json"
        path.write_text(json.dumps(audit), encoding="utf-8")
        return public, metadata, path, audit

    def test_only_exact_verified_absence_resolves_installed_notice_gap(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            public, metadata, audit_path, audit = self.fixture(root)
            with patch("tools.release_contract.software_licenses.ROOT", root):
                report = generate(metadata, root / "notices", root / "report.json")
                self.assertEqual(report["production_notice_review"], "pending")
                report = generate(metadata, root / "notices", root / "report.json", audit_path, public)
                self.assertEqual(report["production_notice_review"], "complete")
                self.assertEqual(len(report["missing_packaged_notice"]), 1)
                self.assertEqual(len(report["excluded_from_client_and_worker"]), 1)
                self.assertEqual(report["unresolved_runtime_notices"], [])
                # Even a zero-rendered module remains conservatively included.
                audit["client"]["modules"] = [{"id": "web/node_modules/missing-runtime/index.js", "package": "missing-runtime", "version": "1.2.3", "rendered_bytes": 0}]
                audit_path.write_text(json.dumps(audit), encoding="utf-8")
                report = generate(metadata, root / "notices", root / "report.json", audit_path, public)
                self.assertEqual(report["production_notice_review"], "pending")
                self.assertEqual(report["unresolved_runtime_notices"], [{"name": "missing-runtime", "version": "1.2.3"}])
                self.assertEqual(report["excluded_from_client_and_worker"], [])

    def test_mutated_missing_extra_unsafe_and_unclassified_code_fail_review(self):
        for kind in ("mutated", "missing", "extra", "unsafe", "unclassified", "unbound-worker"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                public, _, path, audit = self.fixture(Path(directory))
                if kind == "mutated":
                    (public / "entry.js").write_bytes(b"mutated!")
                elif kind == "missing":
                    (public / "entry.js").unlink()
                elif kind == "extra":
                    (public / "unrecorded-worker.js").write_bytes(b"export{}")
                elif kind == "unsafe":
                    audit["client"]["assets"][0]["path"] = "../escape.js"
                elif kind == "unclassified":
                    audit["client"]["modules"] = [{"id": "web/node_modules/missing-runtime/index.js", "package": None, "version": None, "rendered_bytes": 0}]
                elif kind == "unbound-worker":
                    audit["workers"] = [{"modules": [], "assets": [{"path": "worker.js", "bytes": 8, "sha256": "0" * 64}]}]
                path.write_text(json.dumps(audit), encoding="utf-8")
                with self.assertRaises((ValueError, FileNotFoundError)):
                    review_bundle(path, public)

    def test_missing_notice_in_worker_is_not_excluded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            public, metadata, path, audit = self.fixture(root)
            audit["workers"] = [{"modules": [{"id": "web/node_modules/missing-runtime/index.js", "package": "missing-runtime", "version": "1.2.3", "rendered_bytes": 8}], "assets": list(audit["client"]["assets"])}]
            path.write_text(json.dumps(audit), encoding="utf-8")
            with patch("tools.release_contract.software_licenses.ROOT", root):
                report = generate(metadata, root / "notices", root / "report.json", path, public)
            self.assertEqual(report["production_notice_review"], "pending")
            self.assertEqual(report["unresolved_runtime_notices"], [{"name": "missing-runtime", "version": "1.2.3"}])

    def test_powershell_utf16_metadata_retains_the_same_package_facts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            public, metadata, path, _ = self.fixture(root)
            value = metadata.read_text(encoding="utf-8")
            metadata.write_bytes(value.encode("utf-16"))
            with patch("tools.release_contract.software_licenses.ROOT", root):
                report = generate(metadata, root / "notices", root / "report.json", path, public)
            self.assertEqual(report["production_notice_review"], "complete")
            self.assertEqual(report["copied_packages"], len(DIRECT))


if __name__ == "__main__":
    unittest.main()
