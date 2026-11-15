import { isIP } from 'node:net'

// Snapshot status remains visible after loading. Only AtlasView's direct
// loading panel signals an unfinished lookup; nested live regions are facts.
export async function waitForAtlasView(page) {
  await page.locator('.view-page > .status-panel[role=status]').waitFor({state:'hidden'})
}

export async function visitOwner(page,name,ready) {
  await page.getByRole('navigation',{name:'Atlas views'}).getByRole('link',{name,exact:true}).click()
  await page.getByRole('heading',{name:name==='ASN'?'Autonomous systems':name,exact:true,level:1}).waitFor()
  await waitForAtlasView(page);await page.locator(ready).waitFor()
  if(await page.locator('.demo-label').count()||await page.getByRole('alert').count())throw new Error('Production owner route unavailable or labelled synthetic')
  for(const [owner,selector]of Object.entries({Overview:'.fact-list','Observed risk':'.quality-layout','Class C':'.ip-grid',BGP:'.bgp-graph',ASN:'.asn-list'}))
    if(owner!==name&&await page.locator(selector).count())throw new Error('A route duplicated another canonical fact owner')
}

export async function submitLookup(page,q,{releaseId,synthetic=false}) {
  await page.evaluate(()=>{window.__atlasLastLookup=null})
  await page.getByRole('textbox',{name:'IP address or ASN'}).fill(q)
  await page.getByRole('button',{name:'Look up address'}).click()
  await page.waitForFunction(({q,releaseId,synthetic})=>window.__atlasLastLookup?.q===q&&window.__atlasLastLookup.releaseId===releaseId&&window.__atlasLastLookup.synthetic===synthetic,{q,releaseId,synthetic})
  await page.getByRole('heading',{name:isIP(q)?'Overview':'Autonomous systems',exact:true,level:1}).waitFor()
  await waitForAtlasView(page)
  if(await page.getByRole('alert').count()||Boolean(await page.locator('.demo-label').count())!==synthetic)throw new Error('Query did not render its verified release')
}
