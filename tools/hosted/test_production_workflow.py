import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.hosted import production_workflow as workflow
from tools.release_contract.contracts import ContractError


class CandidateClockTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.private = self.root / '.atlas-private'
        self.private.mkdir()
        (self.root / 'build-private').mkdir()
        self.state = self.private / 'state-v1.json'
        self.evaluated_at = 1794700800
        self.state.write_text(json.dumps({'Version': 2, 'EvaluatedAt': '2026-11-15T00:00:00Z'}))
        (self.private / 'workflow-context.json').write_text(json.dumps({'integration_run_id': 10}))
        self.environment = {'ATLAS_UPSTREAM_RUN': '11', 'GITHUB_RUN_ID': '12', 'GITHUB_SHA': 'a' * 40}

    def test_delayed_candidate_uses_intake_clock_only_for_compilation(self):
        with patch.object(workflow, 'ROOT', self.root), patch.dict(os.environ, self.environment), \
                patch.object(workflow.time, 'time', return_value=self.evaluated_at + 600), \
                patch.object(workflow, 'run') as run:
            workflow.candidate()

        commands = [call.args[0] for call in run.call_args_list]
        compile_command, verify_command, corpus_command = commands[:3]
        self.assertEqual(compile_command[1], 'compile-production')
        self.assertEqual(compile_command[compile_command.index('-clock') + 1], self.evaluated_at)
        self.assertEqual(verify_command, ['build-private/atlas', 'verify-production', '-workspace', self.root,
            '-atlas', self.root / 'build-private/production-atlas', '-receipt', self.private / 'production-receipt.json'])
        self.assertEqual(corpus_command[1], 'corpus')
        for command in commands[1:]:
            self.assertNotIn('-clock', command, 'Post-compile validation must use its fresh wall clock')
            self.assertNotIn('--now', command)
        self.assertTrue(any('tools/release_contract/prepare_static.py' in command for command in commands))
        self.assertTrue(any('tools/hosted/production-build.py' in command for command in commands))
        self.assertEqual(commands[-1], ['python', 'tools/hosted/candidate.py', '--public', 'web/.output/public'])
        self.assertEqual(json.loads((self.private / 'workflow-context.json').read_text()), {
            'integration_run_id': 10, 'intake_run_id': 11, 'candidate_run_id': 12, 'head_sha': 'a' * 40})

    def test_invalid_or_future_intake_clock_stops_before_compilation(self):
        valid = {'Version': 2, 'EvaluatedAt': '2026-11-15T00:00:00Z'}
        documents = [[], {}, {**valid, 'Version': 1}, {**valid, 'Version': 2.0}, {**valid, 'Version': True}]
        for stamp in (None, 1794700800, '2026-11-15', '2026-11-15T00:00:00',
                      '2026-11-15T00:00:00+00:00', '2026-11-15T00:00:00.5Z',
                      '2026-02-30T00:00:00Z', '1969-12-31T23:59:59Z', '2026-11-15T00:10:01Z'):
            documents.append({**valid, 'EvaluatedAt': stamp})
        for document in documents:
            with self.subTest(document=document):
                self.state.write_text(json.dumps(document))
                with patch.object(workflow, 'ROOT', self.root), patch.dict(os.environ, self.environment), \
                        patch.object(workflow.time, 'time', return_value=self.evaluated_at + 600), \
                        patch.object(workflow, 'run') as run, self.assertRaises(ContractError):
                    workflow.candidate()
                run.assert_not_called()

    def test_missing_or_malformed_state_has_no_wall_clock_fallback(self):
        for payload in (None, b'{', b'\xff'):
            with self.subTest(payload=payload):
                if payload is None:
                    self.state.unlink()
                else:
                    self.state.write_bytes(payload)
                with patch.object(workflow, 'ROOT', self.root), patch.dict(os.environ, self.environment), \
                        patch.object(workflow, 'run') as run, self.assertRaises((ContractError, OSError)):
                    workflow.candidate()
                run.assert_not_called()

    def test_current_time_verification_failure_prevents_corpus_and_packaging(self):
        def run_command(command, **_):
            if command[1] == 'verify-production':
                raise ContractError('source expired during compilation')

        with patch.object(workflow, 'ROOT', self.root), patch.dict(os.environ, self.environment), \
                patch.object(workflow.time, 'time', return_value=self.evaluated_at + 600), \
                patch.object(workflow, 'run', side_effect=run_command) as run, self.assertRaises(ContractError):
            workflow.candidate()
        self.assertEqual([call.args[0][1] for call in run.call_args_list], ['compile-production', 'verify-production'])
        self.assertFalse((self.root / 'build-private/software-license-metadata.json').exists())


if __name__ == '__main__':
    unittest.main()
