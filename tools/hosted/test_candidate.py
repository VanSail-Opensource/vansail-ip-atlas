import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from tools.hosted.candidate import check_candidate, check_preview_origin, verify_preview
from tools.release_contract.contracts import ContractError, canonical_bytes, make_manifest, parse_canonical, sha256, tree_inventory


class CandidateTests(unittest.TestCase):
    def fixture(self, root):
        obj = b"VIA3" + bytes(124)
        digest = sha256(obj)
        manifest, pointer = make_manifest({"format_version": 3, "schema_version": 3,
            "codec": "zstd-1", "mode": "synthetic", "valid_from": 100, "valid_until": 200,
            "objects": [{"sha256": digest, "bytes": len(obj), "kind": 1, "partition": "all"}]})
        release = parse_canonical(pointer)["release_id"]
        credits = canonical_bytes({"format_version": 1, "release_id": release, "mode": "synthetic", "entries": []})
        credit_hash = sha256(credits)
        credit_index = canonical_bytes({"format_version": 1, "current_release_id": release, "releases": [
            {"release_id": release, "credits_path": f"/_atlas/credits/{credit_hash}.json", "credits_sha256": credit_hash}]})
        files = {"_atlas/current.json": pointer,
            f"_atlas/releases/{release}/manifest.json": manifest,
            f"_atlas/objects/{digest}.via3": obj,
            f"_atlas/credits/{credit_hash}.json": credits,
            "dataset-credits.json": credit_index,
            "ip/index.html": b"<html>synthetic</html>",
            "200.html": b"<html>static fallback</html>",
            "404.html": b"<html>unavailable</html>",
            "_headers": b"/*\n  Content-Security-Policy: default-src 'self'\n  Referrer-Policy: no-referrer\n  X-Content-Type-Options: nosniff\n",
            "_redirects": b"/ /ip 302\n"}
        for path, data in files.items():
            destination = root / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
        entries, tree_hash = tree_inventory(root)
        report = {"status": "passed", "mode": "synthetic", "production_eligible": False,
            "candidate_bundle_sha256": tree_hash, "release_id": release,
            "files": len(entries), "bytes": sum(e[1] for e in entries)}
        return files, report

    def test_frozen_candidate_requires_exact_tree_and_current_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, report = self.fixture(root)
            self.assertEqual(check_candidate(root, report, 150)["release_id"], report["release_id"])
            with self.assertRaises(ContractError):
                check_candidate(root, report, 200)
            (root / "ip/index.html").write_bytes(b"changed after preview")
            with self.assertRaises(ContractError):
                check_candidate(root, report, 150)

    def test_production_and_incomplete_candidate_reports_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, report = self.fixture(root)
            for mutation in ({"mode": "production"}, {"production_eligible": True},
                             {"status": "pending"}, {"files": True}):
                with self.subTest(mutation=mutation), self.assertRaises(ContractError):
                    check_candidate(root, {**report, **mutation}, 150)

    def test_credit_index_must_bind_the_release_even_when_the_tree_digest_matches(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, report = self.fixture(root)
            index_path = root / "dataset-credits.json"
            index = parse_canonical(index_path.read_bytes())
            index["current_release_id"] = "0" * 64
            index_path.write_bytes(canonical_bytes(index))
            entries, digest = tree_inventory(root)
            report = {**report, "candidate_bundle_sha256": digest, "files": len(entries), "bytes": sum(row[1] for row in entries)}
            with self.assertRaises(ContractError):
                check_candidate(root, report, 150)

    def test_only_immutable_https_pages_deployments_are_accepted(self):
        self.assertEqual(check_preview_origin("https://a01b23cd.atlas.pages.dev"),
                         "https://a01b23cd.atlas.pages.dev")
        for url in ("http://a01b23cd.atlas.pages.dev", "https://atlas.pages.dev",
                    "https://main.atlas.pages.dev", "https://a01b23cd.atlas.pages.dev/path",
                    "https://a01b23cd.atlas.pages.dev:443", "https://a01b23cd.atlas.pages.dev?x=1",
                    "https://user:pass@a01b23cd.atlas.pages.dev", "https://127.0.0.1"):
            with self.subTest(url=url), self.assertRaises(ContractError):
                check_preview_origin(url)

    def test_http_preview_identifies_qa_client_instead_of_blocked_library_default(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files, report = self.fixture(root)
            class Response(io.BytesIO):
                def __init__(self, status, headers, body):
                    super().__init__(body)
                    self.status, self.headers = status, headers
            calls = []
            def open_request(request, timeout):
                agent = request.get_header("User-agent", "Python-urllib/default")
                calls.append(agent)
                if agent.startswith("Python-urllib/"):
                    return Response(403, {}, b"error code: 1010")
                path = urlsplit(request.full_url).path
                if path == "/":
                    return Response(302, {"location": "/ip"}, b"")
                name = path.removeprefix("/")
                if name == "ip/":
                    name = "ip/index.html"
                if name in ("200", "404"):
                    name += ".html"
                headers = {"content-security-policy": "default-src 'self'", "referrer-policy": "no-referrer",
                           "x-content-type-options": "nosniff", "cache-control": "public, max-age=0, must-revalidate"}
                if name.startswith(("_atlas/objects/", "_atlas/releases/", "_atlas/credits/")):
                    headers["cache-control"] = "public, max-age=31536000, immutable"
                return Response(200, headers, files[name])
            with patch("tools.hosted.candidate.urllib.request.build_opener") as factory, patch("tools.hosted.candidate.time.time", return_value=150):
                factory.return_value.open = open_request
                result = verify_preview(root, report, "https://a01b23cd.atlas.pages.dev", 150)
            self.assertEqual(result["status"], "passed")
            self.assertTrue(all(agent.startswith("VanSail-IP-Atlas-Preview-QA/") for agent in calls))

    def test_preview_verifies_every_served_byte_and_effective_headers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files, report = self.fixture(root)
            seen = []
            def fetch(path, size):
                seen.append(path)
                headers = {"content-security-policy": "default-src 'self'", "referrer-policy": "no-referrer",
                    "x-content-type-options": "nosniff", "cache-control": "public, max-age=0, must-revalidate"}
                if path == "/":
                    return 302, {"location": "/ip"}, b""
                name = path.removeprefix("/")
                if name == "ip/":
                    name = "ip/index.html"
                if name in ("200", "404"):
                    name += ".html"
                if name.startswith(("_atlas/objects/", "_atlas/releases/", "_atlas/credits/")):
                    headers["cache-control"] = "public, max-age=31536000, immutable"
                return 200, headers, files[name]
            result = verify_preview(root, report, "https://a01b23cd.atlas.pages.dev", 150, fetch)
            self.assertEqual(result["status"], "passed")
            self.assertFalse(result["production_eligible"])
            self.assertIn("/ip/", seen)
            self.assertIn("/200", seen)
            self.assertIn("/404", seen)
            self.assertIn("/dataset-credits.json", seen)
            self.assertTrue(any(path.startswith('/_atlas/credits/') for path in seen))
            self.assertTrue(all("?" not in path and "#" not in path for path in seen))
            self.assertEqual(result["verified_files"], len(files) - 2)
            def corrupt(path, size):
                status, headers, body = fetch(path, size)
                return status, headers, body + (b"x" if path == "/ip/" else b"")
            with self.assertRaises(ContractError):
                verify_preview(root, report, "https://a01b23cd.atlas.pages.dev", 150, corrupt)
            def no_csp(path, size):
                status, headers, body = fetch(path, size)
                headers.pop("content-security-policy", None)
                return status, headers, body
            with self.assertRaises(ContractError):
                verify_preview(root, report, "https://a01b23cd.atlas.pages.dev", 150, no_csp)


if __name__ == "__main__":
    unittest.main()
