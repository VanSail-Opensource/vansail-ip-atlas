import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.hosted import runner_budget as budget


class RunnerBudgetTests(unittest.TestCase):
    def test_chrome_scope_must_share_the_limited_slice(self):
        parent = Path('/sys/fs/cgroup/atlas' + 'a' * 32 + '.slice')
        budget.require_descendant(parent / 'atlas-worker-memory.scope', parent)
        for child in (Path('/sys/fs/cgroup/system.slice/chrome.scope'), parent,
                      parent / '..' / 'escaped.scope'):
            with self.subTest(child=child), self.assertRaises(RuntimeError):
                budget.require_descendant(child, parent)

    def test_effective_limits_reject_unlimited_or_separately_larger_profiles(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            values = {'cpu.max': '200000 100000', 'memory.max': str(budget.MEMORY),
                      'memory.swap.max': '0'}
            for name, value in values.items():
                (root / name).write_text(value)
            self.assertEqual(budget.effective(root)['cpu_quota_us'], 200000)
            for name, value in (('cpu.max', '400000 100000'), ('cpu.max', 'max 100000'),
                                ('memory.max', 'max'), ('memory.swap.max', '1')):
                with self.subTest(name=name, value=value):
                    (root / name).write_text(value)
                    with self.assertRaises(RuntimeError):
                        budget.effective(root)
                    (root / name).write_text(values[name])

    def test_limits_precede_workload_and_slice_is_cleaned_on_failure(self):
        calls = []

        def run(argv, **kwargs):
            calls.append(argv)

        def launch(argv, **kwargs):
            calls.append(argv)
            self.assertEqual(argv[argv.index('--slice') + 1], kwargs['env']['ATLAS_RUNNER_SLICE'])
            self.assertEqual(argv[2:5], ['env', 'PATH='+os.environ['PATH'], '/usr/bin/systemd-run'])
            self.assertIn('/usr/sbin/runuser', argv)
            raise OSError('launch failed')

        with patch('sys.argv', ['runner_budget.py', '--', 'false']), \
             patch.object(budget.subprocess, 'run', side_effect=run), \
             patch.object(budget.subprocess, 'call', side_effect=launch), \
             patch.object(budget, 'slice_cgroup', return_value=Path('/test-slice')), \
             patch.object(budget, 'effective', return_value={}), self.assertRaises(OSError):
            budget.main()
        self.assertEqual(calls[0][1:3], ['systemctl', 'start'])
        self.assertEqual(calls[1][1:4], ['systemctl', 'set-property', '--runtime'])
        self.assertIn('MemoryMax=8G', calls[1])
        self.assertIn('CPUQuota=200%', calls[1])
        self.assertEqual(calls[-1][1:3], ['systemctl', 'stop'])
        self.assertEqual(calls[0][-1], calls[-1][-1])

    def test_workspace_hardlinks_count_disk_allocation_once(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / 'store-package'
            original.write_bytes(b'x' * 8192)
            os.link(original, root / 'installed-package')
            (root / 'symlink').symlink_to(original)
            self.assertEqual(budget.usage(root), original.stat().st_blocks * 512)

    def test_toolchain_roots_are_active_installations_and_counted_once(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            workspace=root/'workspace';workspace.mkdir()
            python=workspace/'tools/python';python.mkdir(parents=True)
            shared=root/'hosted-cache/active-version';(shared/'bin').mkdir(parents=True)
            node=shared/'bin/node';node.write_bytes(b'node')
            unrelated=root/'hosted-cache/unused-version';unrelated.mkdir()
            with patch.object(budget.sys,'prefix',str(python)), \
                 patch.object(budget.shutil,'which',return_value=str(node)), \
                 patch.object(budget.subprocess,'check_output',return_value=str(shared)+'\n') as go:
                installations=budget.toolchain_roots()
            go.assert_called_once()
            self.assertEqual(budget.storage_roots(workspace,installations),[workspace,shared])
            self.assertNotIn(unrelated,budget.storage_roots(workspace,installations))

    def test_missing_node_cannot_silently_omit_toolchain_costs(self):
        with patch.object(budget.shutil,'which',return_value=None), self.assertRaisesRegex(RuntimeError,'Node'):
            budget.toolchain_roots()


if __name__ == '__main__':
    unittest.main()
