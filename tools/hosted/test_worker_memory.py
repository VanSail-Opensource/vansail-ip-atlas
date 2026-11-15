import json
from pathlib import Path
import tempfile
import unittest

from tools.hosted.worker_memory import safe_progress


class WorkerMemoryProgressTests(unittest.TestCase):
    def test_failure_progress_exports_only_known_synthetic_phases(self):
        expected={'phase':'repeat-lookup','case_name':'maximum-live-decoded','completed_cases':1}
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'cases.json'
            path.write_text(json.dumps({'progress':expected,'private_diagnostic':'must not escape'}))
            self.assertEqual(safe_progress(path),expected)
            for change in ({'phase':'private error text'}, {'case_name':'source-rich value'},
                           {'completed_cases':True}, {'completed_cases':4}, {'source_id':'private'}):
                with self.subTest(change=change):
                    path.write_text(json.dumps({'progress':{**expected,**change}}))
                    self.assertIsNone(safe_progress(path))

    def test_missing_or_partial_report_does_not_hide_original_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'cases.json'
            self.assertIsNone(safe_progress(path))
            for payload in (b'{"progress":', b'[]', b'{}', b'{"progress":null}'):
                path.write_bytes(payload)
                self.assertIsNone(safe_progress(path))


if __name__=='__main__':
    unittest.main()
