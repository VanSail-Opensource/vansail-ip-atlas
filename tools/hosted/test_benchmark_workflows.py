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

    def test_complete_preview_joins_all_nine_browser_jobs_on_one_deployment(self):
        jobs=self.workflow('production-preview.yml')['jobs']
        self.assertEqual(set(jobs), {'preview','browser','join'})
        browser=jobs['browser']
        expected={f'{width}-{theme}' for width in (320,390,1280,1440) for theme in ('light','dark')} | {'queries'}
        self.assertEqual(browser['strategy']['fail-fast'], 'false')
        self.assertCountEqual(browser['strategy']['matrix']['shard'], expected)
        self.assertEqual(browser['needs'], 'preview')
        self.assertCountEqual(jobs['join']['needs'], ('preview','browser'))
        for job in jobs.values():
            self.assertEqual(job['runs-on'],'ubuntu-24.04')
            self.assertEqual(job['environment'],'atlas-preview')
            self.assertTrue(any('context --kind preview' in step.get('run','') for step in job['steps']))
            self.assertTrue(any('restore --kind benchmark' in step.get('run','') for step in job['steps']))
        uploads=lambda job: [s['with'] for s in jobs[job]['steps'] if s.get('uses','').startswith('actions/upload-artifact')]
        self.assertEqual([a['name'] for a in uploads('preview')], ['atlas-preview-inputs-${{ github.run_attempt }}'])
        self.assertEqual(uploads('browser')[0]['path'], 'reports/production-browser-part.json')
        self.assertEqual(uploads('browser')[0]['name'], 'atlas-browser-part-${{ github.run_attempt }}-${{ matrix.shard }}')
        self.assertFalse(any('CLOUDFLARE_API_TOKEN' in str(jobs[job]) for job in ('browser','join')))
        parts=next(s['with'] for s in jobs['join']['steps'] if 'pattern' in s.get('with',{}))
        self.assertEqual(parts['pattern'],'atlas-browser-part-${{ github.run_attempt }}-*')
        self.assertEqual(parts['merge-multiple'],'false')
        self.assertIn('production-preview-evidence', [a['name'] for a in uploads('join')])

if __name__=='__main__':unittest.main()
