import assert from 'node:assert/strict'
import { after, before, test } from 'node:test'
import { chromium } from 'playwright'
import { visitOwner, submitLookup, waitForAtlasView } from './production-interactions.mjs'

let browser
before(async()=>{browser=await chromium.launch({channel:'chrome',headless:true,...(process.env.ATLAS_CHROME_EXECUTABLE?{executablePath:process.env.ATLAS_CHROME_EXECUTABLE}:{})})})
after(async()=>{await browser?.close()})

async function pageWithSnapshot() {
  const page=await browser.newPage()
  await page.setContent(`<nav aria-label="Atlas views"><a href="#bgp" onclick="document.querySelector('h1').textContent='BGP'">BGP</a></nav>
    <section class="view-page"><h1>Overview</h1>
      <label>IP address or ASN<input></label><button>Look up address</button>
      <p class="status-panel glass" role="status">Opening the atlas…</p>
      <div class="bgp-controls">Observed route controls</div><section class="rpki-snapshots"><h2>Origin-specific RPKI</h2>
        <p>Snapshot result: valid<span class="rpki-expired" role="status"> · Expired snapshot</span></p>
      </section>
    </section>`)
  return page
}

async function completeLoading(page,pending,completed) {
  // These are independent browser tasks, so a mistakenly skipped loading wait
  // settles before the real panel is removed. Keep the RPKI live region intact.
  await page.waitForTimeout(100)
  assert.equal(completed(),false,'The real loading panel was ignored')
  assert.equal(await page.locator('.rpki-expired').isVisible(),true)
  await page.locator('.view-page > .status-panel[role=status]').evaluate(node=>node.remove())
  await pending
  assert.equal(await page.locator('.rpki-expired').isVisible(),true)
}

test('production owner navigation finishes with expired RPKI visible, after actual loading',{timeout:10000},async()=>{
  const page=await pageWithSnapshot()
  try {
    let completed=false
    const pending=visitOwner(page,'BGP','.bgp-controls').then(()=>{completed=true})
    await page.getByRole('heading',{name:'BGP',level:1}).waitFor()
    await completeLoading(page,pending,()=>completed)
    await assert.rejects(page.locator('.view-page [role=status]').waitFor({state:'hidden',timeout:100}),/Timeout/)
  } finally {await page.close()}
})

test('production submission keeps visible snapshot status and still binds the exact answer',{timeout:10000},async()=>{
  const page=await pageWithSnapshot(),releaseId='a'.repeat(64)
  try {
    await page.evaluate(releaseId=>{
      document.querySelector('button').onclick=()=>{window.__atlasLastLookup={q:document.querySelector('input').value,releaseId,synthetic:false}}
    },releaseId)
    let completed=false
    const pending=submitLookup(page,'1.1.1.1',{releaseId}).then(()=>{completed=true})
    await page.waitForFunction(()=>window.__atlasLastLookup?.q==='1.1.1.1')
    await completeLoading(page,pending,()=>completed)
    assert.equal((await page.locator('.rpki-snapshots').innerText()).includes('Snapshot result: valid'),true)
  } finally {await page.close()}
})

test('the loading wait also completes when no live status is rendered',{timeout:10000},async()=>{
  const page=await browser.newPage()
  try {await page.setContent('<section class="view-page"><h1>Overview</h1></section>');await waitForAtlasView(page)}
  finally {await page.close()}
})

test('IPv6 subnet navigation admits its distinct title but rejects a duplicated summary',{timeout:10000},async()=>{
  const page=await browser.newPage()
  try {
    await page.setContent(`<nav aria-label="Atlas views">
      <a href="#subnet" onclick="document.querySelector('h1').textContent='IPv6 subnet risk'">Class C</a>
      <a href="#overview" onclick="document.querySelector('h1').textContent='Overview';document.querySelector('.view-page').append(Object.assign(document.createElement('dl'),{className:'fact-list',textContent:'Overview fact'}))">Overview</a>
    </nav><section class="view-page"><h1>Overview</h1><section class="subnet-summary">Subnet summary</section></section>`)
    await visitOwner(page,'Class C','.subnet-summary',{heading:'IPv6 subnet risk'})
    await assert.rejects(visitOwner(page,'Overview','.fact-list'),/duplicated another canonical fact owner/)
  } finally {await page.close()}
})
