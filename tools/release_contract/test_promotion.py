import copy
import io
import json
import stat
import unittest
from unittest.mock import patch
import zipfile

from tools.release_contract.contracts import ContractError, sha256
from tools.release_contract.promotion import REPOSITORY, TrustedCI, extract_reports, json_object


def archive(entries):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as bundle:
        for name, data, mode in entries:
            entry = zipfile.ZipInfo(name)
            entry.external_attr = mode << 16
            bundle.writestr(entry, data)
    return output.getvalue()


class TrustedEvidenceTests(unittest.TestCase):
    def test_source_free_archive_allowlist_and_regular_files_are_exact(self):
        regular = stat.S_IFREG | 0o644
        data = archive([("report.json", b'{"raw":1}', regular)])
        self.assertEqual(extract_reports(data, {"report.json"}), {"report.json": b'{"raw":1}'})
        for entries in ([('../report.json', b'{}', regular)], [('report.json', b'{}', stat.S_IFLNK | 0o777)],
                        [('report.json', b'{}', regular), ('sources.yaml', b'private', regular)],
                        [('report.json', b'{}', regular), ('report.json', b'{}', regular)]):
            with self.subTest(entries=entries), self.assertRaises(ContractError):
                extract_reports(archive(entries), {"report.json"})

    def test_duplicate_and_nonfinite_report_fields_fail(self):
        for data in (b'{"status":"failed","status":"passed"}', b'{"time":NaN}', b'[]'):
            with self.subTest(data=data), self.assertRaises(ContractError):
                json_object(data)

    def test_exact_head_successful_main_workflow_and_repository_are_independent(self):
        head = "a" * 40
        good = {"status": "completed", "conclusion": "success", "head_sha": head, "head_branch": "main",
                "event": "workflow_dispatch", "path": ".github/workflows/production-candidate.yml",
                "head_repository": {"full_name": REPOSITORY}}
        ci = TrustedCI()
        with patch.object(ci, "_get", return_value=json.dumps(good).encode()):
            self.assertEqual(ci.run(1, head, good["path"]), good)
        for change in ({"conclusion": "failure"}, {"status": "in_progress"}, {"head_sha": "b" * 40},
                       {"head_branch": "feature"}, {"event": "pull_request"}, {"path": ".github/workflows/untrusted.yml"},
                       {"head_repository": {"full_name": "another/repository"}}):
            with self.subTest(change=change), patch.object(ci, "_get", return_value=json.dumps({**good, **change}).encode()), self.assertRaises(ContractError):
                ci.run(1, head, good["path"])

    def test_api_digest_size_originating_run_and_archive_bytes_are_bound(self):
        ci = TrustedCI()
        data = archive([(name, b'{}', stat.S_IFREG | 0o644) for name in ("static-candidate.json", "production-build.json")])
        digest, head = sha256(data), "a" * 40
        metadata = {"name": "production-candidate-evidence", "expired": False, "workflow_run": {"id": 1, "head_sha": head},
                    "digest": "sha256:" + digest, "size_in_bytes": len(data)}
        def request(route):
            return data if route.endswith('/zip') else json.dumps(metadata).encode()
        with patch.object(ci, "run"), patch.object(ci, "_get", side_effect=request):
            self.assertEqual(set(ci.reports("candidate", 1, 2, digest, head)), {"static-candidate.json", "production-build.json"})
        for field, value in (("expired", True), ("size_in_bytes", len(data) + 1), ("digest", "sha256:" + "0" * 64),
                             ("workflow_run", {"id": 9, "head_sha": head}), ("name", "private-sources")):
            changed = {**metadata, field: value}
            with self.subTest(field=field), patch.object(ci, "run"), patch.object(ci, "_get", side_effect=lambda route: data if route.endswith('/zip') else json.dumps(changed).encode()), self.assertRaises(ContractError):
                ci.reports("candidate", 1, 2, digest, head)


if __name__ == "__main__":
    unittest.main()
