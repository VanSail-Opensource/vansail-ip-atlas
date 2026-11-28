import { test } from 'node:test'
import assert from 'node:assert/strict'
import { auditRealDiagnostic, realDiagnosticPlan } from './real-a11y-diagnostic.mjs'

const origin = new URL('https://cfc6ff95.vansail-ip-atlas.pages.dev')
const env = {GITHUB_ACTIONS:'true',GITHUB_REPOSITORY:'VanSail-Opensource/vansail-ip-atlas',
  GITHUB_REF:'refs/heads/codex/real-a11y-diagnostic',ATLAS_REAL_A11Y_DIAGNOSTIC:'light'}

test('the diagnostic cannot run in main, on other previews, or with a qualifying shard', () => {
  assert.equal(realDiagnosticPlan({},origin),null)
  assert.deepEqual(realDiagnosticPlan(env,origin),{populations:[{width:320,theme:'light'}],queries:false,identity:null})
  assert.throws(()=>realDiagnosticPlan({...env,GITHUB_REF:'refs/heads/main'},origin))
  assert.throws(()=>realDiagnosticPlan({...env,ATLAS_PREVIEW_SHARD:'320-light'},origin))
  assert.throws(()=>realDiagnosticPlan(env,new URL('https://aaaa1234.vansail-ip-atlas.pages.dev')))
})

test('the diagnostic groups only allowlisted rule, route, category and reason labels', async () => {
  const oldWindow=globalThis.window, oldDocument=globalThis.document
  const sampled={target:['#raw-selector'],any:[{data:{messageKey:'elmPartiallyObscured',forbidden:'not-for-logs'}}],all:[],none:[]}
  globalThis.document={querySelector:()=>({closest:selector=>selector==='.view-nav'})}
  globalThis.window={axe:{run:async()=>({violations:[],incomplete:[
    {id:'color-contrast',nodes:[sampled,sampled]},
    {id:'raw-unrecognized-rule',nodes:[{...sampled,target:[['nested','selector']],any:[{data:{messageKey:'raw-reason'}}]}]},
  ]})}}
  let calls=0
  const page={evaluate:async fn=>++calls<3?null:fn()}
  try {
    const rows=await auditRealDiagnostic(page,'dummy-axe-source','bgp')
    assert.deepEqual(rows,[
      {outcome:'incomplete',rule:'color-contrast',category:'navigation',reason:'elmPartiallyObscured',count:2,route:'bgp'},
      {outcome:'incomplete',rule:'other',category:'other',reason:'other',count:1,route:'bgp'},
    ])
    await assert.rejects(auditRealDiagnostic(page,'dummy-axe-source','untrusted-route-value'))
  } finally {
    globalThis.window=oldWindow
    globalThis.document=oldDocument
  }
})
