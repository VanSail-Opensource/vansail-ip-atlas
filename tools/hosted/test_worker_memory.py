import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from tools.hosted.worker_memory import memory_snapshot, record_memory_sample, safe_progress, sample_workload_memory


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

    def test_cgroup_memory_diagnostics_preserve_raw_peak_and_allowlist(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'memory.current').write_text('100')
            (root/'memory.peak').write_text('999')
            (root/'memory.stat').write_text('anon 70\nfile 20\nkernel 10\npgfault 123\n')
            self.assertEqual(memory_snapshot(root),{
                'current_bytes':100,'peak_bytes':999,'stat_bytes':{'anon':70,'file':20,'kernel':10}})

    def test_sampled_diagnostics_keep_only_two_maximum_observations(self):
        summary={'sample_count':0}
        first={'phase':'first-lookup','case_name':'maximum-materialized-answer','completed_cases':0}
        repeat={'phase':'repeat-lookup','case_name':'maximum-materialized-answer','completed_cases':0}
        record_memory_sample(summary,{'current_bytes':300,'peak_bytes':350,
            'stat_bytes':{'anon':250,'file':50,'private_diagnostic':123}},first,1)
        record_memory_sample(summary,{'current_bytes':200,'peak_bytes':400,
            'stat_bytes':{'anon':100,'file':100}},repeat,2)
        for i in range(1000):
            record_memory_sample(summary,{'current_bytes':100,'peak_bytes':400,
                'stat_bytes':{'anon':80,'file':20}},None,3+i)
        self.assertEqual(summary['sample_count'],1002)
        self.assertEqual(set(summary),{'sample_count','highest_sampled_current','latest_observed_peak_increase'})
        highest=summary['highest_sampled_current'];latest=summary['latest_observed_peak_increase']
        self.assertEqual((highest['current_bytes'],highest['workload_progress']),(300,first))
        self.assertEqual(highest['stat_bytes'],{'anon':250,'file':50})
        self.assertEqual((latest['peak_bytes'],latest['workload_progress']),(400,repeat))

    def test_sampler_read_failure_and_teardown_preserve_workload_exception(self):
        attempted=threading.Event()
        def failed_read(_):
            attempted.set()
            raise OSError('private diagnostic must not escape')
        with patch('tools.hosted.worker_memory.memory_snapshot',side_effect=failed_read):
            with self.assertRaisesRegex(TimeoutError,'original workload timeout'):
                with sample_workload_memory(Path('/unused'),Path('/unused')) as summary:
                    self.assertTrue(attempted.wait(1))
                    raise TimeoutError('original workload timeout')
        self.assertTrue(summary['sampling_stopped'])
        self.assertGreaterEqual(summary['read_error_count'],1)
        self.assertEqual(summary['sample_count'],0)
        self.assertNotIn('private diagnostic',json.dumps(summary))


if __name__=='__main__':
    unittest.main()
