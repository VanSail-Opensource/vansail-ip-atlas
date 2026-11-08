// Runs against the exact prepared static tree. Local execution is not hosted acceptance.
import { chromium } from 'playwright'
import assert from 'node:assert/strict'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { createHash } from 'node:crypto'
const base = process.env.ATLAS_PREVIEW_URL ?? 'http://127.0.0.1:4173'
const candidate = JSON.parse(await readFile(new URL('../../reports/static-candidate.json', import.meta.url), 'utf8'))
if (candidate.status !== 'passed' || !/^[0-9a-f]{64}$/.test(candidate.candidate_bundle_sha256) || !/^[0-9a-f]{64}$/.test(candidate.release_id))
  throw new Error('A verified prepared static candidate is required before browser regression')
const browser = await chromium.launch({ channel: 'chrome', headless: true })
const report = { mode: base.includes('127.0.0.1') ? 'local-synthetic' : 'hosted-preview', browser: browser.version(), node: process.versions.node, url: base,
  candidate_bundle_sha256: candidate.candidate_bundle_sha256, release_id: candidate.release_id, tests: [], network: [], errors: [] }
await mkdir(new URL('../../reports/', import.meta.url), { recursive: true })
let context
try {
  context = await browser.newContext({ viewport: { width: 1280, height: 900 }, reducedMotion: 'reduce' })
  const page = await context.newPage()
  page.on('pageerror', error => report.errors.push(error.message))
  context.on('request', request => {
    const url = new URL(request.url())
    if (url.origin !== new URL(base).origin && url.protocol !== 'data:') {
      report.network.push(url.origin)
      assert.equal(url.origin, 'https://tile.openstreetmap.org', `Unexpected external request: ${url.origin}`)
      assert(!request.headers().referer, 'Query-bearing referrer must never reach tiles')
    }
  })
  // Tiles are not needed to verify atlas logic; avoid dependency on their availability.
  await page.route('https://tile.openstreetmap.org/**', route => route.fulfill({ status: 200, contentType: 'image/png', body: Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+j9zEAAAAASUVORK5CYII=', 'base64') }))
  async function test(name, fn) {
    try { await fn(); report.tests.push({ name, status: 'passed' }) }
    catch (error) { report.tests.push({ name, status: 'failed', error: String(error) }); throw error }
  }
  await test('actual HTTP root redirect', async () => {
    const response = await context.request.get(`${base}/`, { maxRedirects: 0 })
    assert.equal(response.status(), 302); assert.equal(response.headers().location, '/ip')
  })
  await test('every immutable atlas object is served with its declared hash', async () => {
    const pointerResponse = await context.request.get(`${base}/_atlas/current.json`)
    assert.equal(pointerResponse.status(), 200)
    const pointer = await pointerResponse.json()
    assert.equal(pointer.release_id, report.release_id)
    const manifestResponse = await context.request.get(`${base}${pointer.manifest_path}`)
    assert.equal(manifestResponse.status(), 200)
    const manifestBytes = await manifestResponse.body()
    assert.equal(createHash('sha256').update(manifestBytes).digest('hex'), pointer.manifest_sha256)
    const manifest = JSON.parse(manifestBytes)
    assert.equal(manifest.release_id, pointer.release_id)
    for (const object of manifest.objects) {
      const response = await context.request.get(`${base}/_atlas/objects/${object.sha256}.via3`)
      assert.equal(response.status(), 200)
      const bytes = await response.body()
      assert.equal(bytes.length, object.bytes)
      assert.equal(createHash('sha256').update(bytes).digest('hex'), object.sha256)
    }
  })
  await test('hero single input and local validation', async () => {
    await page.goto(`${base}/ip/`); await page.getByRole('textbox', { name: 'IP address or ASN' }).waitFor()
    assert.equal(await page.locator('input').count(), 1)
    assert.equal(await page.locator('.edge-glow').count(), 1)
    let dataRequests = 0
    const count = request => { if (new URL(request.url()).pathname.startsWith('/_atlas/')) dataRequests++ }
    page.on('request', count)
    await page.getByRole('textbox').fill('no-such-host.invalid')
    await page.getByRole('button', { name: 'Look up address' }).click()
    await page.getByRole('alert').waitFor()
    assert.equal(dataRequests, 0); page.off('request', count)
  })
  await test('hero is visible in prerendered HTML before JavaScript', async () => {
    const isolated = await browser.newContext({ javaScriptEnabled: false })
    try {
      const initial = await isolated.newPage()
      await initial.goto(`${base}/ip/`)
      assert.equal(await initial.getByRole('heading', { level: 1 }).count(), 1)
      assert.equal(await initial.getByRole('textbox').count(), 1)
      assert.equal(await initial.locator('.hero-inner').evaluate(node => getComputedStyle(node).opacity), '1')
    } finally { await isolated.close() }
  })
  for (const view of ['overview', 'quality', 'class-c', 'bgp', 'asn']) {
    await test(`canonical ${view} owner`, async () => {
      await page.goto(`${base}/ip/${view}/?q=203.0.113.1`)
      await page.locator('.demo-label').waitFor({ timeout: 20000 })
      assert.equal(await page.getByRole('alert').count(), 0)
      const owners = { '.map-panel': 'overview', '.score-value': 'quality', '.ip-grid': 'class-c', '.bgp-graph': 'bgp', '.asn-card': 'asn' }
      await page.locator(Object.keys(owners).find(selector => owners[selector] === view)).first().waitFor({ timeout: 20000 })
      for (const [selector, owner] of Object.entries(owners)) assert.equal((await page.locator(selector).count()) > 0, owner === view)
      for (const width of [320, 390, 1280, 1440]) {
        await page.setViewportSize({ width, height: 900 })
        assert(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), `Horizontal overflow on ${view} at ${width}`)
      }
      if (view === 'class-c') {
        assert.equal(await page.getByRole('gridcell').count(), 256)
        await page.getByRole('gridcell').first().focus(); await page.keyboard.press('ArrowDown')
        assert.equal(await page.getByRole('gridcell').nth(16).getAttribute('tabindex'), '0')
      }
      if (view === 'bgp') {
        const svg = page.locator('.bgp-graph svg')
        await svg.focus(); await page.keyboard.press('ArrowRight'); await page.keyboard.press('+')
        await page.getByRole('button', { name: 'Fit', exact: true }).click()
        const before = await page.locator('.graph-node').evaluateAll(nodes => nodes.map(node => node.getAttribute('transform')))
        await page.getByRole('combobox', { name: 'Focus observed route' }).selectOption('0')
        assert.deepEqual(await page.locator('.graph-node').evaluateAll(nodes => nodes.map(node => node.getAttribute('transform'))), before)
        const options = await page.getByRole('combobox', { name: 'Select announcing origin' }).locator('option').count()
        assert.equal(options, 2)
      }
    })
  }
  await test('downloaded BGP SVG is standalone and keeps geometry under route focus', async () => {
    await page.goto(`${base}/ip/bgp/?q=203.0.113.1`)
    await page.locator('.graph-node').first().waitFor()
    const focus = page.getByRole('combobox', { name: 'Focus observed route' })
    const exports = []
    for (const selection of ['-1', '0']) {
      await focus.selectOption(selection)
      const pending = page.waitForEvent('download')
      await page.getByRole('button', { name: 'Export', exact: true }).click()
      const download = await pending
      assert.match(download.suggestedFilename(), /^AS\d+-observed-paths\.svg$/)
      assert.equal(await download.failure(), null)
      const stream = await download.createReadStream()
      const chunks = []
      for await (const chunk of stream) chunks.push(chunk)
      const xml = Buffer.concat(chunks).toString('utf8')
      const parsed = await page.evaluate(xml => {
        const document = new DOMParser().parseFromString(xml, 'image/svg+xml')
        const svg = document.documentElement
        return { error: document.querySelector('parsererror')?.textContent, namespace: svg.namespaceURI,
          xmlns: svg.getAttribute('xmlns'), width: svg.getAttribute('width'), height: svg.getAttribute('height'),
          title: svg.querySelector(':scope > title')?.textContent, description: svg.querySelector(':scope > desc')?.textContent,
          edgePaint: [...svg.querySelectorAll('.graph-edge')].map(node => ({ stroke: node.getAttribute('stroke'), fill: node.getAttribute('fill') })),
          textPaint: [...svg.querySelectorAll('.graph-node text')].map(node => ({ fill: node.getAttribute('fill'), font: node.getAttribute('font-family') })),
          geometry: [...svg.querySelectorAll('.graph-edge, .graph-node')].map(node => [node.getAttribute('d'), node.getAttribute('transform')]),
          externalReferences: svg.querySelectorAll('script, image, use, foreignObject, [href]').length }
      }, xml)
      assert(!parsed.error)
      assert.equal(parsed.namespace, 'http://www.w3.org/2000/svg')
      assert.equal(parsed.xmlns, 'http://www.w3.org/2000/svg')
      assert.equal(parsed.width, '800'); assert.equal(parsed.height, '380')
      assert.match(parsed.title, /observed AS paths/)
      assert.match(parsed.description, /bounded projection/)
      assert(parsed.edgePaint.length > 0 && parsed.textPaint.length > 0)
      for (const edge of parsed.edgePaint) { assert(edge.stroke && edge.stroke !== 'none'); assert.equal(edge.fill, 'none') }
      for (const label of parsed.textPaint) { assert(label.fill && label.fill !== 'none'); assert(label.font) }
      assert.equal(parsed.externalReferences, 0)
      exports.push(parsed)
      await writeFile(new URL(`../../reports/bgp-export-${selection === '-1' ? 'all' : 'focused'}.svg`, import.meta.url), xml)
    }
    assert.deepEqual(exports[1].geometry, exports[0].geometry)
  })
  await test('IPv6 Class C not applicable', async () => {
    await page.goto(`${base}/ip/class-c/?q=2001%3Adb8%3A%3A1`)
    await page.getByRole('heading', { name: 'IPv4 only' }).waitFor()
    assert.equal(await page.getByRole('gridcell').count(), 0)
  })
  await test('unknown IPv4 retains an unknown 256-cell view', async () => {
    await page.goto(`${base}/ip/class-c/?q=8.8.8.8`)
    await page.getByRole('grid').waitFor()
    assert.equal(await page.getByRole('gridcell').count(), 256)
    assert.equal(await page.locator('.ip-grid .observed').count(), 0)
    assert.equal(await page.getByRole('heading', { name: 'IPv4 only' }).count(), 0)
  })
  await test('unknown IPv4 BGP has no invented origin', async () => {
    await page.goto(`${base}/ip/bgp/?q=8.8.8.8`)
    await page.getByRole('heading', { name: 'No observed origin' }).waitFor()
    assert.equal(await page.locator('.graph-node').count(), 0)
  })
  await test('URL normalization, origin errors and repeated query rejection', async () => {
    await page.goto(`${base}/ip/overview/?q=AS13335`)
    await page.locator('.asn-card').first().waitFor()
    assert(new URL(page.url()).pathname.includes('/ip/asn'))
    await page.goto(`${base}/ip/bgp/?q=203.0.113.1&origin=AS174`)
    await page.getByRole('alert').waitFor(); assert.match(await page.getByRole('alert').innerText(), /does not announce/)
    await page.goto(`${base}/ip/quality/?q=203.0.113.1&q=8.8.8.8`)
    await page.getByRole('alert').waitFor()
  })
  await test('light/dark and responsive widths', async () => {
    await page.goto(`${base}/ip/overview/?q=203.0.113.1`)
    await page.locator('.demo-label').waitFor()
    await page.getByRole('button', { name: 'Toggle color theme' }).click()
    for (const width of [320, 390, 1280, 1440]) {
      await page.setViewportSize({ width, height: 900 })
      assert(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), `Horizontal overflow at ${width}`)
    }
    await page.screenshot({ path: new URL('../../reports/overview-dark.png', import.meta.url).pathname.replace(/^\/(.:\/)/, '$1'), fullPage: true })
    await page.getByRole('button', { name: 'Toggle color theme' }).click()
    await page.goto(`${base}/ip/`)
    await page.screenshot({ path: new URL('../../reports/hero.png', import.meta.url).pathname.replace(/^\/(.:\/)/, '$1'), fullPage: true })
  })
  await test('corrupt worker input fails without rendering partial facts', async () => {
    const isolated = await browser.newContext({ serviceWorkers: 'block' })
    try {
      await isolated.route('**/_atlas/objects/*.via3', async route => {
        const response = await route.fetch()
        const bytes = await response.body()
        bytes[bytes.length - 1] ^= 1
        await route.fulfill({ response, body: bytes })
      })
      const broken = await isolated.newPage()
      broken.on('pageerror', error => report.errors.push(error.message))
      await broken.goto(`${base}/ip/overview/?q=203.0.113.1`)
      await broken.getByRole('alert').waitFor({ timeout: 20000 })
      assert.match(await broken.getByRole('alert').innerText(), /could not be verified/)
      assert.equal(await broken.locator('.demo-label, .map-panel, .asn-card').count(), 0)
    } finally { await isolated.close() }
  })
  await test('a cancelled slow query cannot replace a newer query', async () => {
    const isolated = await browser.newContext({ serviceWorkers: 'block' })
    let release
    const gate = new Promise(resolve => { release = resolve })
    let first = true
    try {
      await isolated.route('**/_atlas/current.json', async route => {
        if (first) { first = false; await gate }
        await route.continue().catch(() => {}) // The earlier request is cancelled.
      })
      const late = await isolated.newPage()
      late.on('pageerror', error => report.errors.push(error.message))
      const started = late.waitForRequest('**/_atlas/current.json')
      await late.goto(`${base}/ip/overview/?q=203.0.113.1`)
      await started
      await late.getByRole('textbox').fill('8.8.8.8')
      await late.getByRole('button', { name: 'Look up address' }).click()
      // The second query must complete while the first is still held back.
      await late.locator('.demo-label').waitFor({ timeout: 20000 })
      assert.equal(new URL(late.url()).searchParams.get('q'), '8.8.8.8')
      assert.equal(await late.getByRole('textbox').inputValue(), '8.8.8.8')
      assert(!await late.locator('.fact-list').innerText().then(text => text.includes('Atlas Harbor')))
      release()
      await late.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))))
      assert.equal(await late.getByRole('textbox').inputValue(), '8.8.8.8')
      assert.equal(await late.getByRole('alert').count(), 0)
    } finally { release(); await isolated.close() }
  })
  assert.deepEqual(report.errors, [], 'Browser runtime errors')
  report.status = 'passed'
} catch (error) { report.status = 'failed'; report.failure = String(error); process.exitCode = 1 }
finally {
  await writeFile(new URL('../../reports/ui-regression.json', import.meta.url), JSON.stringify(report, null, 2) + '\n')
  await context?.close(); await browser.close()
  console.log(JSON.stringify({ status: report.status, tests: report.tests, errors: report.errors, failure: report.failure }, null, 2))
}
