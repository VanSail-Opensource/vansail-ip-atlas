// Diagnostic only. This module cannot create an acceptance report or deploy.
import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'

const origin = 'https://cfc6ff95.vansail-ip-atlas.pages.dev'
const head = 'e1ace20b002f483e4c45b5f5178464a65126309d'
const release = 'f9a13e8edad7fdeccbfeee724f26e65efb2f36c4797dcafd4d734d437f8d0a6f'
const bundle = '570207e2337d358f279f0d899704d0d388bad46eedeb8a8abf04dcb0e0145545'
const allowedCorpus = '66581ee581f7d101aa2799c2d01fb6a6b5856bffa3f0dc7c6d5877d873e2976d'
const routes = ['hero','overview','quality','class-c','asn','bgp','unknown-terminal-bgp']

export function realDiagnosticPlan(env, base) {
  const theme = env.ATLAS_REAL_A11Y_DIAGNOSTIC
  if (theme === undefined) return null
  if (!['light','dark'].includes(theme) || base.origin !== origin || env.GITHUB_ACTIONS !== 'true' ||
      env.GITHUB_REPOSITORY !== 'VanSail-Opensource/vansail-ip-atlas' ||
      env.GITHUB_REF !== 'refs/heads/codex/real-a11y-diagnostic' || env.ATLAS_PREVIEW_SHARD !== undefined) throw new Error('diagnostic context')
  return { populations: [{width:320,theme}], queries:false, identity:null }
}

export async function verifyRealDiagnosticInputs(root, candidate, corpusBytes) {
  const deployment=JSON.parse(await readFile(new URL('reports/pages-deployment.json',root),'utf8'))
  if (deployment.status !== 'verified' || deployment.operation !== 'preview' || deployment.environment !== 'preview' ||
      deployment.url.replace(/\/$/,'') !== origin || deployment.head_sha !== head || deployment.release_id !== release ||
      deployment.candidate_bundle_sha256 !== bundle || candidate.release_id !== release || candidate.candidate_bundle_sha256 !== bundle ||
      createHash('sha256').update(corpusBytes).digest('hex') !== allowedCorpus) throw new Error('diagnostic inputs')
}

export async function auditRealDiagnostic(page, axeSource, route) {
  if (!routes.includes(route)) throw new Error('diagnostic route')
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))))
  await page.evaluate(axeSource)
  const result=await page.evaluate(async () => {
    const audit=await window.axe.run(document,{runOnly:{type:'tag',values:['wcag2a','wcag2aa','wcag21aa']}})
    const rules=['color-contrast','scrollable-region-focusable','svg-img-alt','label','nested-interactive','target-size',
      'link-in-text-block','button-name','link-name','aria-valid-attr','aria-valid-attr-value','heading-order']
    const reasons=['bgOverlap','elmPartiallyObscured','elmPartiallyObscuring','outsideViewport','bgImage','bgGradient','imgNode',
      'fgAlpha','colorParse','pseudoContent','complexTextShadows','emptyValue','shortTextContent','equalRatio','nonBmp','fgContrast','hidden']
    const categories=[['graph-node-label','.graph-node-label'],['graph-empty-label','.empty-graph-label'],['graph-toolbar','.graph-toolbar'],
      ['graph-legend','.graph-legend'],['graph-caption','.graph-caption'],['graph-original','.graph-original'],['graph-viewport','.graph-viewport'],
      ['bgp-control','.bgp-controls'],['rpki','.rpki-snapshots'],['tier1','.tier1-list'],['navigation','.view-nav'],['asn-prefix','.prefix-list'],
      ['asn','.asn-list,.asn-card'],['overview','.fact-list,.fact-panel'],['grid','.ip-grid'],['grid-detail','.cell-detail'],
      ['subnet','.subnet-summary'],['reason','.reason-chip'],['quality','.quality-layout,.score-panel'],['search','.search-form'],
      ['header','.site-header'],['footer','.site-footer'],['view-heading','.view-heading'],['status','.status-panel']]
    const findings=[]
    for (const outcome of ['violations','incomplete']) {
      const counts=new Map()
      for (const result of audit[outcome]) for (const node of result.nodes) {
        let el=null
        try {if (node.target.length===1 && typeof node.target[0]==='string') el=document.querySelector(node.target[0])} catch {}
        const rule=rules.includes(result.id)?result.id:'other'
        const category=categories.find(([,selector])=>el?.closest(selector))?.[0]??'other'
        const reason=[...node.any,...node.all,...node.none].map(check=>check.data?.messageKey).find(k=>reasons.includes(k))??'other'
        const key=[rule,category,reason].join('/')
        let row=counts.get(key)
        if (!row) {row={outcome,rule,category,reason,count:0};counts.set(key,row)}
        row.count++
      }
      findings.push(...counts.values())
    }
    return findings
  })
  return result.map(value=>({...value,route}))
}
