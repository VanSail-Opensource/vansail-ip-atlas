from pathlib import Path
import unittest
import yaml

ROOT=Path(__file__).resolve().parents[2]

class BenchmarkWorkflowChainTests(unittest.TestCase):
    def workflow(self,name):
        return yaml.load((ROOT/'.github/workflows'/name).read_text(),Loader=yaml.BaseLoader)

    def test_dispatch_resets_chain_and_join_consumes_completed_matrix(self):
        relay=self.workflow('production-benchmark-dispatch.yml')
        matrix=self.workflow('production-benchmarks.yml')
        join=self.workflow('production-benchmark-join.yml')
        preview=self.workflow('production-preview.yml')
        promotion=self.workflow('production-promotion.yml')
        self.assertEqual(set(matrix['on']),{'workflow_dispatch'})
        self.assertEqual(relay['on']['workflow_run']['workflows'],['Atlas qualified production candidate'])
        self.assertEqual(join['on']['workflow_run']['workflows'],[matrix['name']])
        self.assertEqual(preview['on']['workflow_run']['workflows'],[join['name']])
        self.assertEqual(promotion['on']['workflow_run']['workflows'],[preview['name']])
        for workflow in (relay,join,preview,promotion):
            self.assertEqual(workflow['on']['workflow_run']['types'],['completed'])
        self.assertEqual(relay['permissions']['actions'],'write')
        self.assertNotIn('secrets.',str(relay))
        for workflow in (matrix,join): self.assertEqual(workflow['permissions']['actions'],'read')

    def test_all_fifteen_independent_cases_keep_final_budget_and_original_candidate(self):
        matrix=self.workflow('production-benchmarks.yml')['jobs']['benchmark']
        strategy=matrix['strategy']
        self.assertEqual(strategy['fail-fast'],'false')
        self.assertEqual(len(strategy['matrix']['scenario'])*len(strategy['matrix']['sample']),15)
        self.assertEqual(matrix['runs-on'],'ubuntu-24.04')
        steps=matrix['steps']
        measured=next(i for i,s in enumerate(steps) if ' benchmark-case ' in s.get('run',''))
        uploaded=next(i for i,s in enumerate(steps) if s.get('uses','').startswith('actions/upload-artifact'))
        self.assertLess(measured,uploaded)
        self.assertIn('runner_budget.py --report reports/runner-budget.json',steps[measured]['run'])
        self.assertEqual(set(steps[uploaded]['with']['path'].split()),{'reports/production-build-case.json','reports/runner-budget.json'})
        self.assertIn('github.run_attempt',steps[uploaded]['with']['name'])
        preview=self.workflow('production-preview.yml')['jobs']['preview']['steps']
        self.assertTrue(any('restore --kind benchmark' in step.get('run','') for step in preview))
        public=next(step for step in preview if step.get('with',{}).get('name')=='atlas-production-public')
        self.assertEqual(public['with']['run-id'],'${{ steps.candidate.outputs.run_id }}')

if __name__=='__main__':unittest.main()
