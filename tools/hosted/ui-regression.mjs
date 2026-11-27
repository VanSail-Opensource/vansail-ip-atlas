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
    if (url.origin !== new URL(base).origin && url.protocol !== 'data:') report.network.push(url.origin)
  })
  await context.route('**/*', route => new URL(route.request().url()).origin === new URL(base).origin
    ? route.continue() : route.abort('blockedbyclient'))
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
  await test('global dataset credits stay release scoped and reveal no synthetic data associations', async () => {
    const isolated = await browser.newContext({ serviceWorkers: 'block' })
    const creditRequests = [], external = [], atlasRequests = []
    isolated.on('request', request => {
      const url = new URL(request.url())
      if (url.origin !== new URL(base).origin && url.protocol !== 'data:') external.push(url.origin)
      if (url.pathname.startsWith('/_atlas/')) atlasRequests.push(url.pathname)
      if (url.pathname === '/dataset-credits.json' || /^\/_atlas\/credits\/[0-9a-f]{64}\.json$/.test(url.pathname)) {
        creditRequests.push(url.pathname)
        assert.equal(url.search, '', 'A dataset-credit request must never carry the lookup query')
        assert.equal(url.hash, '')
        assert(!request.headers().referer, 'A credit request must not carry a query-bearing referrer')
      }
    })
    try {
      const creditsPage = await isolated.newPage()
      creditsPage.on('pageerror', error => report.errors.push(error.message))
      await creditsPage.goto(`${base}/ip/`)
      await creditsPage.getByRole('textbox', { name: 'IP address or ASN' }).waitFor()
      const details = creditsPage.getByTestId('dataset-credits')
      assert.equal(await details.count(), 1)
      assert.equal(await details.locator('summary').innerText(), 'Dataset credits')
      assert.equal(creditRequests.length, 0, 'Credits must load only after the user opens them')
      assert.equal(atlasRequests.length, 0, 'The unopened hero must not request atlas data')
      let expectedCreditPath
      const openAndAssertEmptyCredits = async () => {
        const indexResponse = creditsPage.waitForResponse(response => new URL(response.url()).pathname === '/dataset-credits.json')
        const documentResponse = creditsPage.waitForResponse(response => /^\/_atlas\/credits\/[0-9a-f]{64}\.json$/.test(new URL(response.url()).pathname))
        await details.locator('summary').click()
        const indexResult = await indexResponse
        assert.equal(indexResult.status(), 200)
        const index = await indexResult.json()
        assert.deepEqual(Object.keys(index).sort(), ['current_release_id', 'format_version', 'releases'])
        assert.equal(index.format_version, 1)
        assert.equal(index.current_release_id, report.release_id)
        assert(index.releases.length >= 1 && index.releases.length <= 2)
        const entry = index.releases.find(entry => entry.release_id === report.release_id)
        assert(entry, 'Credits index must contain the currently pinned release')
        assert.deepEqual(Object.keys(entry).sort(), ['credits_path', 'credits_sha256', 'release_id'])
        assert.match(entry.credits_sha256, /^[0-9a-f]{64}$/)
        assert.equal(entry.credits_path, `/_atlas/credits/${entry.credits_sha256}.json`)
        expectedCreditPath = entry.credits_path
        const response = await documentResponse
        assert.equal(response.status(), 200)
        assert.equal(new URL(response.url()).pathname, entry.credits_path)
        const bytes = await response.body()
        assert.equal(createHash('sha256').update(bytes).digest('hex'), entry.credits_sha256)
        const credit = JSON.parse(bytes)
        assert.deepEqual(Object.keys(credit).sort(), ['entries', 'format_version', 'mode', 'release_id'])
        assert.equal(credit.format_version, 2)
        assert.equal(credit.release_id, report.release_id)
        assert.equal(credit.mode, 'synthetic')
        assert.deepEqual(credit.entries, [], 'Candidate datasets are never credited as included synthetic data')
        await details.getByText('Synthetic preview. No third-party IP datasets are included.', { exact: true }).waitFor()
        assert.equal(await details.getByTestId('dataset-credit').count(), 0)
        assert.equal(await details.locator('a').count(), 0)
        assert.equal(await details.locator('[data-source-id], [data-ip], [data-asn]').count(), 0)
        assert.equal(await details.evaluate(node => Boolean(node.closest('.view-page'))), false)
      }
      await openAndAssertEmptyCredits()
      assert(atlasRequests.every(path => path.startsWith('/_atlas/credits/')), 'Opening global hero credits must not initiate an IP lookup')
      const emptyText = await details.innerText()
      for (const q of ['203.0.113.1', '8.8.8.8']) {
        await creditsPage.goto(`${base}/ip/quality/?q=${q}`)
        await creditsPage.locator('.demo-label').waitFor({ timeout: 20000 })
        assert.equal(await details.count(), 1)
        await openAndAssertEmptyCredits()
        assert.equal(await details.innerText(), emptyText, 'Global credits must not vary by queried IP')
        assert(!(await details.innerText()).includes(q))
      }
      assert.deepEqual(creditRequests, ['/dataset-credits.json', expectedCreditPath,
        '/dataset-credits.json', expectedCreditPath, '/dataset-credits.json', expectedCreditPath])
      assert.deepEqual(external, [], 'Expanding dataset credits must not contact a dataset origin')
      report.dataset_credit_checks = { scope: 'global-release-only', mode: 'synthetic', entries: 0,
        requests: creditRequests, external_requests: 0, query_associations: 0 }
    } finally { await isolated.close() }
  })
  await test('production facts wait for verified credits and keep publisher links visible', async () => {
    // Isolated HTTP controls exercise the real worker/controller with a mock
    // production-mode manifest. These bytes never enter the frozen candidate.
    const canonical = value => Array.isArray(value) ? `[${value.map(canonical).join(',')}]`
      : value && typeof value === 'object' ? `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}` : JSON.stringify(value)
    const pointer = await (await context.request.get(`${base}/_atlas/current.json`)).json()
    const original = await (await context.request.get(`${base}${pointer.manifest_path}`)).json()
    const { release_id: ignored, ...descriptor } = original
    descriptor.mode = 'production'
    const releaseId = createHash('sha256').update(canonical(descriptor)).digest('hex')
    const manifest = Buffer.from(canonical({ ...descriptor, release_id: releaseId }))
    const mockPointer = canonical({ format_version: 3, release_id: releaseId, manifest_path: `/_atlas/releases/${releaseId}/manifest.json`, manifest_sha256: createHash('sha256').update(manifest).digest('hex') })
    const logoFixture = JSON.parse(await readFile(new URL('../../fixtures/contracts/dataset-logos-v1.json', import.meta.url), 'utf8')).cases[0]
    const logo = { path: `/_atlas/legal/${logoFixture.sha256}.png`, sha256: logoFixture.sha256, alt: 'Synthetic publisher logo' }
    const entry = { logo, name: 'Legal placement fixture', text: 'Isolated placement check, never included in candidate data.', url: 'https://publisher.example/credit' }
    const document = Buffer.from(canonical({ format_version: 2, release_id: releaseId, mode: 'production', entries: [entry] }))
    const hash = createHash('sha256').update(document).digest('hex'), creditPath = `/_atlas/credits/${hash}.json`
    const index = canonical({ format_version: 1, current_release_id: releaseId, releases: [{ release_id: releaseId, credits_path: creditPath, credits_sha256: hash }] })
    for (const [view, corruption] of [['quality', 'none'], ['quality', 'document'], ['class-c', 'logo'], ['class-c', 'none']]) {
      const selector = view === 'quality' ? '.quality-layout' : '.class-layout'
      const isolated = await browser.newContext({ serviceWorkers: 'block' })
      // Advance only the page's periodic refresh while the authenticated
      // credit response is still held. Worker clocks and lease checks run
      // normally, and the original foreground request must remain alive.
      await isolated.addInitScript(() => {
        const timer = window.setInterval
        window.setInterval = function (callback, delay, ...args) {
          if (delay === 60_000 && typeof callback === 'function') window.__atlasRefresh = () => callback(...args)
          return timer.call(window, callback, delay, ...args)
        }
      })
      let releaseCredit, requested, creditRequests = 0
      const delay = new Promise(resolve => { releaseCredit = resolve }), started = new Promise(resolve => { requested = resolve })
      try {
        await isolated.route('**/_atlas/current.json', route => route.fulfill({ contentType: 'application/json', body: mockPointer }))
        await isolated.route(`**/_atlas/releases/${releaseId}/manifest.json`, route => route.fulfill({ contentType: 'application/json', body: manifest }))
        await isolated.route('**/dataset-credits.json', route => route.fulfill({ contentType: 'application/json', body: index }))
        await isolated.route(`**${creditPath}`, async route => { creditRequests++; requested(); await delay; await route.fulfill({ contentType: 'application/json', body: corruption === 'document' ? '{}' : document }) })
        await isolated.route(`**${logo.path}`, route => route.fulfill({ contentType: 'image/png', body: corruption === 'logo' ? Buffer.from('invalid') : Buffer.from(logoFixture.base64, 'base64') }))
        const creditPage = await isolated.newPage()
        await creditPage.goto(`${base}/ip/${view}/?q=203.0.113.1`)
        await Promise.race([started, new Promise((_, reject) => setTimeout(() => reject(new Error('Credit verification did not start')), 20000))])
        assert(await creditPage.getByRole('status').isVisible())
        assert.equal(await creditPage.locator(selector).count(), 0, 'Production facts must wait for credit integrity')
        await creditPage.evaluate(() => {
          if (typeof window.__atlasRefresh !== 'function') throw new Error('Periodic refresh was not registered')
          window.__atlasRefresh()
        })
        releaseCredit()
        if (corruption !== 'none') {
          await creditPage.getByRole('alert').waitFor()
          assert.equal(await creditPage.locator(selector).count(), 0, 'Unverified legal metadata cannot leave production facts visible')
        } else {
          await creditPage.locator(selector).waitFor()
          const visible = creditPage.getByTestId('visible-dataset-credits')
          assert.equal(creditRequests, 1, 'A periodic refresh must not restart an in-flight foreground verification')
          assert.equal(await visible.getAttribute('role'), 'group')
          assert(await visible.isVisible())
          assert.equal(await visible.locator('a').getAttribute('href'), entry.url)
          assert.equal(await visible.locator('img').getAttribute('src'), 'data:image/png;base64,' + logoFixture.base64)
          assert.equal(await visible.locator('img').getAttribute('alt'), logo.alt)
          const details = creditPage.getByTestId('dataset-credits')
          assert(await details.evaluate(node => node.open), 'Required full notices open when production data first appears')
          await details.locator('summary').click()
          assert(await visible.isVisible(), 'Required credit remains visible after collapsing notices')
          assert.equal(await creditPage.locator('.demo-label').count(), 0)
        }
      } finally { releaseCredit(); await isolated.close() }
    }
    report.production_credit_fixture = { scope: 'isolated-intercept-only-not-candidate-data', delayed_facts: true, corrupted_document_rejected: true, corrupted_logo_rejected: true, class_c_waits_for_credits: true, visible_collapsed_credit: true }
  })
  await test('global credit renderer escapes notices and exposes safe keyboard-accessible links', async () => {
    // An isolated HTTP mock exercises a nonempty legal display. It is never
    // written to the candidate and does not claim inclusion of a real dataset.
    const isolated = await browser.newContext({ serviceWorkers: 'block' })
    const canonical = value => Array.isArray(value) ? `[${value.map(canonical).join(',')}]`
      : value && typeof value === 'object' ? `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}` : JSON.stringify(value)
    const entry = { name: 'Legal display fixture', text: 'Synthetic notice: <strong>plain text</strong>.',
      url: 'https://publisher.example/credit', license_url: 'https://publisher.example/license' }
    const body = Buffer.from(canonical({ format_version: 2, release_id: report.release_id, mode: 'production', entries: [entry] }))
    const hash = createHash('sha256').update(body).digest('hex'), path = `/_atlas/credits/${hash}.json`
    const index = canonical({ format_version: 1, current_release_id: report.release_id,
      releases: [{ release_id: report.release_id, credits_path: path, credits_sha256: hash }] })
    const external = []
    isolated.on('request', request => { if (new URL(request.url()).origin !== new URL(base).origin) external.push(request.url()) })
    try {
      await isolated.route('**/dataset-credits.json', route => route.fulfill({ contentType: 'application/json', body: index }))
      await isolated.route(`**${path}`, route => route.fulfill({ contentType: 'application/json', body }))
      const creditPage = await isolated.newPage()
      await creditPage.goto(`${base}/ip/`)
      const details = creditPage.getByTestId('dataset-credits')
      await details.locator('summary').focus(); await creditPage.keyboard.press('Enter')
      const credit = details.getByTestId('dataset-credit')
      await credit.waitFor()
      assert.equal(await credit.count(), 1)
      assert.equal(await credit.locator('p').innerText(), entry.text)
      assert.equal(await credit.locator('strong').count(), 0, 'Legal text must never become markup')
      const links = credit.locator('a')
      assert.equal(await links.count(), 2)
      for (const [i, href] of [entry.url, entry.license_url].entries()) {
        const link = links.nth(i)
        assert.equal(await link.getAttribute('href'), href)
        assert.equal(await link.getAttribute('target'), '_blank')
        assert.equal(await link.getAttribute('rel'), 'noopener noreferrer')
        assert.equal(await link.getAttribute('referrerpolicy'), 'no-referrer')
      }
      const visibleCredits = creditPage.getByTestId('visible-dataset-credits')
      assert(await visibleCredits.isVisible(), 'Required credit links must be visible outside the disclosure')
      await details.locator('summary').click()
      assert(await visibleCredits.isVisible(), 'Closing full notices must not hide the required publisher credit')
      assert.deepEqual(external, [], 'Displaying credits must not fetch the publisher or license origin')
      report.credit_renderer_fixture = { scope: 'isolated-intercept-only-not-candidate-data', entries: 1, external_requests: 0 }
    } finally { await isolated.close() }
  })
  for (const view of ['overview', 'quality', 'class-c', 'bgp', 'asn']) {
    await test(`canonical ${view} owner`, async () => {
      await page.goto(`${base}/ip/${view}/?q=203.0.113.1`)
      await page.locator('.demo-label').waitFor({ timeout: 20000 })
      assert.equal(await page.getByTestId('dataset-credits').count(), 1, 'One shared global credits display per view')
      assert.equal(await page.getByRole('alert').count(), 0)
      const owners = { '.fact-list': 'overview', '.score-value': 'quality', '.ip-grid,.subnet-summary': 'class-c', '.bgp-graph': 'bgp', '.asn-card': 'asn' }
      await page.locator(Object.keys(owners).find(selector => owners[selector] === view)).first().waitFor({ timeout: 20000 })
      for (const [selector, owner] of Object.entries(owners)) assert.equal((await page.locator(selector).count()) > 0, owner === view)
      if (view === 'overview') {
        const values = await page.locator('.fact-list > div').evaluateAll(rows => Object.fromEntries(
          rows.map(row => [row.querySelector('dt').textContent.trim(), row.querySelector('dd').textContent.trim()]),
        ))
        assert.deepEqual(values, { Country: 'US', 'Registration country': 'GB', 'Matched prefix': '203.0.113.0/24', Usage: 'residential' })
        assert.equal(await page.locator('.map-panel, .map-empty, .geo-map, .leaflet-container').count(), 0)
      }
      for (const width of [320, 390, 1280, 1440]) {
        await page.setViewportSize({ width, height: 900 })
        assert(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), `Horizontal overflow on ${view} at ${width}`)
      }
      if (view === 'class-c') {
        assert.equal(await page.getByRole('gridcell').count(), 256)
        // Three fixture scores sum to 125, but the mean includes all 256 addresses.
        assert.equal((await page.getByTestId('subnet-risk-mean').innerText()).trim(), '0.48828 / 100')
        await page.getByRole('gridcell').first().focus(); await page.keyboard.press('ArrowDown')
        assert.equal(await page.getByRole('gridcell').nth(16).getAttribute('tabindex'), '0')
      }
      if (view === 'bgp') {
        const assertGraphSurface = async () => {
          const surface = await page.locator('.bgp-graph').evaluate(element => ({
            backdrop: getComputedStyle(element).backdropFilter,
            background: getComputedStyle(element).backgroundColor,
            edgeMask: getComputedStyle(element.querySelector('.edge-accent')).maskImage,
            edgeLight: getComputedStyle(element.querySelector('.edge-accent')).backgroundImage,
          }))
          assert.equal(surface.backdrop, 'none', 'The interactive SVG must not invalidate a backdrop blur on every frame')
          assert.notEqual(surface.background, 'rgba(0, 0, 0, 0)', 'The graph retains its themed surface backing')
          assert.notEqual(surface.edgeLight, 'none', 'The graph retains its edge lighting')
          assert.notEqual(surface.edgeMask, 'none', 'The graph retains masked edge lighting')
        }
        await assertGraphSurface()
        await page.getByRole('button', { name: 'Toggle color theme' }).click()
        await assertGraphSurface()
        await page.getByRole('button', { name: 'Toggle color theme' }).click()
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
  await test('RPKI snapshot expiry remains visible and preserves graph state across timer and resume', async () => {
    const pointer = await (await context.request.get(`${base}/_atlas/current.json`)).json()
    const manifest = await (await context.request.get(`${base}${pointer.manifest_path}`)).json()
    const isolated = await browser.newContext({ viewport: { width: 1280, height: 900 }, reducedMotion: 'reduce' })
    try {
      const snapshot = await isolated.newPage()
      snapshot.on('pageerror', error => report.errors.push(error.message))
      await snapshot.clock.install({ time: new Date(manifest.valid_from * 1000) })
      await snapshot.goto(`${base}/ip/bgp/?q=203.0.113.1`)
      const valid = snapshot.locator('[data-rpki-origin="13335"]')
      const invalid = snapshot.locator('[data-rpki-origin="15169"]')
      await valid.waitFor()
      // Let Nuxt's hydration/idle scheduling finish before controlling timers.
      await snapshot.clock.pauseAt(await snapshot.evaluate(() => Date.now() + 1000))
      assert.match(await valid.innerText(), /Snapshot result: valid/)
      assert.match(await invalid.innerText(), /Snapshot result: invalid.*Coverage expired/)
      assert.deepEqual(await invalid.locator('dt').allTextContents(), ['Observed', 'Coverage expiry'])
      assert.deepEqual(await valid.locator('dt').allTextContents(), ['Observed', 'Authorization expiry'])
      assert.equal(await valid.locator('.rpki-expired').count(), 0)
      const clocks = await valid.locator('dd').allTextContents()
      assert.equal(clocks.length, 2)
      const observedAt = Date.parse(clocks[0]), expiry = Date.parse(clocks[1])
      assert(Number.isFinite(observedAt) && observedAt < manifest.valid_from * 1000)
      assert(Number.isFinite(expiry) && expiry > manifest.valid_from * 1000 && expiry < manifest.valid_until * 1000)
      const svg = snapshot.locator('.bgp-graph svg')
      await snapshot.getByRole('combobox', { name: 'Focus observed route' }).selectOption('0')
      await svg.focus(); await snapshot.keyboard.press('ArrowRight'); await snapshot.keyboard.press('+')
      const original = await svg.elementHandle()
      const transform = await svg.locator(':scope > g').getAttribute('transform')
      const checkPreserved = async () => {
        assert(await original.evaluate(node => node === document.querySelector('.bgp-graph svg')), 'Snapshot timing must not remount the graph')
        assert.equal(await svg.locator(':scope > g').getAttribute('transform'), transform)
        assert.equal(await snapshot.getByRole('combobox', { name: 'Focus observed route' }).inputValue(), '0')
        assert.match(await valid.innerText(), /Snapshot result: valid/)
        assert.deepEqual(await valid.locator('dd').allTextContents(), clocks)
      }
      await snapshot.clock.setSystemTime(expiry - 1000)
      await snapshot.clock.runFor(1000)
      await valid.locator('.rpki-expired').waitFor()
      assert.match(await valid.innerText(), /Snapshot result: valid.*Authorization expired/)
      await checkPreserved()
      // A tab suspended across the deadline must refresh immediately on resume.
      await snapshot.clock.setSystemTime(expiry - 1000)
      const resumed = snapshot.waitForResponse('**/_atlas/current.json')
      await snapshot.evaluate(() => document.dispatchEvent(new Event('visibilitychange')))
      await resumed
      await valid.locator('.rpki-expired').waitFor({ state: 'detached' })
      await checkPreserved()
      await snapshot.clock.setSystemTime(expiry)
      await snapshot.evaluate(() => document.dispatchEvent(new Event('visibilitychange')))
      await valid.locator('.rpki-expired').waitFor()
      await checkPreserved()
      for (const width of [320, 390, 1280, 1440]) {
        await snapshot.setViewportSize({ width, height: 900 })
        assert(await snapshot.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `RPKI dates overflow at ${width}`)
      }
      await snapshot.clock.setSystemTime(manifest.valid_until * 1000)
      await snapshot.evaluate(() => document.dispatchEvent(new Event('visibilitychange')))
      await snapshot.getByRole('alert').waitFor()
      assert.equal(await snapshot.locator('.rpki-snapshots, .bgp-graph').count(), 0, 'Whole-release expiry still removes ineligible facts')
      report.rpki_snapshot_checks = { observed_status_retained: true, timer_expiry: true, resume_expiry: true,
        graph_state_preserved: true, whole_release_expiry_enforced: true }
    } finally { await isolated.close() }
  })
  await test('routing relationships and evidenced intermediate ASN labels are legible on narrow light and dark views', async () => {
    const palettes = []
    for (const theme of ['light', 'dark']) {
      const isolated = await browser.newContext({ viewport: { width: 320, height: 844 }, colorScheme: theme, reducedMotion: 'reduce' })
      try {
        await isolated.addInitScript(theme => {
          localStorage.setItem('nuxt-color-mode', theme)
          window.graphNameBatches = 0
          const post = Worker.prototype.postMessage
          Worker.prototype.postMessage = function (message, ...rest) {
            if (message.action === 'graphNames') window.graphNameBatches++
            return post.call(this, message, ...rest)
          }
        }, theme)
        const graph = await isolated.newPage()
        await graph.goto(`${base}/ip/bgp/?q=AS13335`)
        await graph.locator('.graph-node-label').filter({ hasText: 'Atlas Access' }).waitFor()
        const legend = graph.getByRole('list', { name: 'Relationship legend' })
        assert.deepEqual(await legend.getByRole('listitem').allTextContents(), ['Upstream', 'Peer', 'Customer', 'Sibling', 'Unknown'])
        const paint = await legend.evaluate(list => {
          const rgb = color => color.match(/[\d.]+/g).slice(0, 3).map(Number)
          const luminance = color => rgb(color).reduce((sum, value, index) => {
            const s = value / 255
            return sum + [0.2126, 0.7152, 0.0722][index] * (s <= 0.04045 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4)
          }, 0)
          const background = luminance(getComputedStyle(list.closest('.graph-caption')).backgroundColor)
          return [...list.querySelectorAll('.relation-sample')].map(sample => {
            const style = getComputedStyle(sample), y = luminance(style.backgroundColor)
            return { color: style.backgroundColor, pattern: style.maskImage, contrast: (Math.max(y, background) + 0.05) / (Math.min(y, background) + 0.05) }
          })
        })
        assert.equal(new Set(paint.map(sample => sample.color)).size, 5)
        assert.equal(new Set(paint.map(sample => sample.pattern)).size, 5)
        assert(paint.every(sample => sample.contrast >= 3))
        palettes.push(paint.map(sample => sample.color))
        assert.deepEqual(await graph.locator('.graph-node-label').allTextContents(), ['AS3356', 'Atlas Transit', 'Atlas Access'])
        assert.deepEqual(await graph.locator('.graph-node title').allTextContents(), ['AS3356', 'Atlas Transit · AS13335', 'Atlas Access · AS15169'])
        const edges = await graph.locator('.graph-edge').evaluateAll(edges => edges.map(edge => ({ relation: edge.dataset.relation,
          color: getComputedStyle(edge).stroke, title: edge.querySelector('title').textContent })))
        assert.deepEqual(edges, [
          { relation: 'transit_upstream', color: paint[0].color, title: 'AS13335 → AS15169: transit upstream; observed adjacency; original hops 0 → 1; inferred relationship' },
          { relation: 'transit_upstream', color: paint[0].color, title: 'AS15169 → AS3356: transit upstream; observed adjacency; original hops 1 → 2; inferred relationship' },
        ])
        assert.deepEqual(await graph.locator('.tier1-list p').allTextContents(), ['AS13335 · global transit'])
        const before = await graph.locator('.graph-node').evaluateAll(nodes => nodes.map(node => node.getAttribute('transform')))
        await graph.getByRole('combobox', { name: 'Focus observed route' }).selectOption('0')
        await graph.getByRole('button', { name: 'Fit', exact: true }).click()
        assert.deepEqual(await graph.locator('.graph-node').evaluateAll(nodes => nodes.map(node => node.getAttribute('transform'))), before)
        await graph.locator('.graph-original summary').click()
        assert.equal(await graph.locator('.graph-original code').textContent(), 'sequence [AS13335 AS15169 AS3356]')
        assert(await graph.evaluate(() => document.documentElement.scrollWidth <= innerWidth))
        assert.equal(await graph.evaluate(() => window.graphNameBatches), 1)
      } finally { await isolated.close() }
    }
    assert.notDeepEqual(...palettes)
  })
  await test('downloaded BGP SVG is standalone and keeps geometry under route focus', async () => {
    await page.goto(`${base}/ip/bgp/?q=203.0.113.1`)
    await page.locator('.graph-node').first().waitFor()
    const focus = page.getByRole('combobox', { name: 'Focus observed route' })
    const liveViewBox = await page.locator('.bgp-graph svg').evaluate(svg => ({
      value: svg.getAttribute('viewBox'), width: svg.viewBox.baseVal.width, height: svg.viewBox.baseVal.height,
    }))
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
          viewBox: svg.getAttribute('viewBox'),
          background: { width: svg.querySelector(':scope > rect')?.getAttribute('width'), height: svg.querySelector(':scope > rect')?.getAttribute('height') },
          title: svg.querySelector(':scope > title')?.textContent, description: svg.querySelector(':scope > desc')?.textContent,
          edgePaint: [...svg.querySelectorAll('.graph-edge')].map(node => ({ stroke: node.getAttribute('stroke'), fill: node.getAttribute('fill') })),
          textPaint: [...svg.querySelectorAll('.graph-node text')].map(node => ({ fill: node.getAttribute('fill'), font: node.getAttribute('font-family') })),
          geometry: [...svg.querySelectorAll('.graph-edge, .graph-node')].map(node => [node.getAttribute('d'), node.getAttribute('transform')]),
          externalReferences: svg.querySelectorAll('script, image, use, foreignObject, [href]').length }
      }, xml)
      assert(!parsed.error)
      assert.equal(parsed.namespace, 'http://www.w3.org/2000/svg')
      assert.equal(parsed.xmlns, 'http://www.w3.org/2000/svg')
      assert.equal(Number(parsed.width), liveViewBox.width); assert.equal(Number(parsed.height), liveViewBox.height)
      assert.equal(parsed.viewBox, liveViewBox.value)
      assert.equal(Number(parsed.background.width), liveViewBox.width); assert.equal(Number(parsed.background.height), liveViewBox.height)
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
  await test('24-node graph keeps readable default spacing and exports its full dynamic bounds', async () => {
    const populations = []
    for (const width of [320, 390, 1280, 1440]) {
      await page.setViewportSize({ width, height: 900 })
      await page.goto(`${base}/ip/bgp/?q=AS424240`)
      await page.locator('.graph-node').nth(23).waitFor()
      const svg = page.locator('.bgp-graph svg')
      const geometry = await svg.evaluate(svg => {
        const box = element => { const r = element.getBoundingClientRect(); return { left:r.left, top:r.top, right:r.right, bottom:r.bottom, width:r.width, height:r.height } }
        return { svg:box(svg), bounds:{ width:svg.viewBox.baseVal.width, height:svg.viewBox.baseVal.height },
          items:[...svg.querySelectorAll('.graph-node')].flatMap((node,index) => ['circle','.graph-node-label'].map(kind =>
            ({ id:`${index}:${kind}`, ...box(node.querySelector(kind)) }))),
          layout:[...svg.querySelectorAll('.graph-node')].map(node => node.getAttribute('transform')) }
      })
      assert.equal(geometry.items.length, 48)
      assert.equal(await page.locator('.graph-edge').count(), 23)
      assert.equal(await page.locator('.graph-edge[data-relation="unknown"]').count(), 23)
      assert((await page.locator('.graph-edge title').allTextContents()).every(title => title.includes(': unknown; observed adjacency') && !title.includes('inferred relationship')))
      for (const box of geometry.items) {
        assert(box.width > 0 && box.height > 0, `Empty graph content ${box.id} at width ${width}`)
        assert(box.left >= geometry.svg.left - .5 && box.right <= geometry.svg.right + .5 &&
          box.top >= geometry.svg.top - .5 && box.bottom <= geometry.svg.bottom + .5,
        `Graph content ${box.id} clipped by world bounds at width ${width}`)
      }
      for (let a=0;a<geometry.items.length;a++) for (let b=a+1;b<geometry.items.length;b++) {
        const x=geometry.items[a],y=geometry.items[b]
        assert(!(x.left < y.right && y.left < x.right && x.top < y.bottom && y.top < x.bottom),
          `Graph content overlaps: ${x.id} / ${y.id} at width ${width}`)
      }
      assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `Graph caused page overflow at ${width}`)
      const viewport = page.locator('.graph-viewport')
      const scroll = await viewport.evaluate(element => {
        const maximum=element.scrollWidth-element.clientWidth
        element.scrollLeft=maximum
        const reached=element.scrollLeft
        element.scrollLeft=0
        return { maximum,reached }
      })
      if (scroll.maximum > 1) assert(scroll.reached > 0, 'The readable graph must remain horizontally reachable')
      await page.getByRole('button', { name:'Fit', exact:true }).click()
      const fitted = await viewport.evaluate(element => ({ viewport:element.clientWidth, content:element.scrollWidth, scroll:element.scrollLeft }))
      assert(fitted.content <= fitted.viewport + 1 && fitted.scroll === 0, 'Fit must reveal the complete graph width')
      await svg.scrollIntoViewIfNeeded()
      assert(await svg.evaluate(svg => {
        const r=svg.getBoundingClientRect()
        return [...svg.querySelectorAll('.graph-node circle')].every(node => {
          const b=node.getBoundingClientRect()
          return b.left>=Math.max(0,r.left) && b.right<=Math.min(innerWidth,r.right) && b.top>=Math.max(0,r.top) && b.bottom<=Math.min(innerHeight,r.bottom)
        })
      }), 'Fit must show every node inside the SVG and screen')
      if (width===320) {
        const toolbar=await page.locator('.bgp-graph').evaluate(panel => {
          const r=panel.getBoundingClientRect()
          return { labels:[...panel.querySelectorAll('.graph-actions button')].map(button => button.textContent.trim()),
            clipped:[...panel.querySelectorAll('.graph-actions button')].some(button => {const b=button.getBoundingClientRect();return b.left<r.left || b.right>r.right || b.left<0 || b.right>innerWidth}) }
        })
        assert.deepEqual(toolbar.labels,['Export','Actual size','Fit'])
        assert.equal(toolbar.clipped,false,'All fitted graph controls remain reachable at320px')
        assert(await page.evaluate(() => document.documentElement.scrollWidth<=innerWidth),'Fitted graph controls must not overflow the narrow page')
      }
      assert.deepEqual(await page.locator('.graph-node').evaluateAll(nodes => nodes.map(node => node.getAttribute('transform'))), geometry.layout)
      await page.getByRole('combobox', { name:'Focus observed route' }).selectOption('11')
      assert.deepEqual(await page.locator('.graph-node').evaluateAll(nodes => nodes.map(node => node.getAttribute('transform'))), geometry.layout)
      await page.getByRole('combobox', { name:'Focus observed route' }).selectOption('-1')
      populations.push({ width, nodes:24, world_bounds:geometry.bounds, overlapping_items:0, clipped_items:0, default_scroll_max:scroll.maximum })
    }
    const bounds = await page.locator('.bgp-graph svg').evaluate(svg => ({ width:svg.viewBox.baseVal.width,height:svg.viewBox.baseVal.height,value:svg.getAttribute('viewBox') }))
    const pending = page.waitForEvent('download')
    await page.getByRole('button', { name:'Export',exact:true }).click()
    const download = await pending
    assert.equal(await download.failure(),null)
    const chunks=[]
    for await (const chunk of await download.createReadStream()) chunks.push(chunk)
    const xml=Buffer.concat(chunks).toString('utf8')
    const exported=await page.evaluate(xml => {
      const document=new DOMParser().parseFromString(xml,'image/svg+xml'),svg=document.documentElement,background=svg.querySelector(':scope > rect')
      return { error:document.querySelector('parsererror')?.textContent,width:Number(svg.getAttribute('width')),height:Number(svg.getAttribute('height')),
        viewBox:svg.getAttribute('viewBox'),backgroundWidth:Number(background?.getAttribute('width')),backgroundHeight:Number(background?.getAttribute('height')),
        nodes:svg.querySelectorAll('.graph-node').length,edges:svg.querySelectorAll('.graph-edge').length }
    },xml)
    assert(!exported.error)
    assert.equal(exported.width,bounds.width);assert.equal(exported.height,bounds.height);assert.equal(exported.viewBox,bounds.value)
    assert.equal(exported.backgroundWidth,bounds.width);assert.equal(exported.backgroundHeight,bounds.height)
    assert.equal(exported.nodes,24);assert.equal(exported.edges,23)
    await writeFile(new URL('../../reports/bgp-export-24.svg',import.meta.url),xml)
    report.graph_readability_populations=populations
  })
  await test('IPv6 /48 summaries distinguish observed evidence from zero without a grid', async () => {
    for (const [query, prefix, average, observed] of [
      ['2001:db8::1', '2001:db8::/48', '0.00015 / 100', 1],
      ['2001:db8:1::1', '2001:db8:1::/48', '0 / 100', 0],
    ]) {
      await page.goto(`${base}/ip/class-c/?q=${encodeURIComponent(query)}`)
      await page.getByRole('heading', { name: 'IPv6 subnet risk', level: 1, exact: true }).waitFor()
      const summary = page.locator('.subnet-summary'), mean = summary.getByTestId('subnet-risk-mean')
      await mean.waitFor()
      assert.equal(await summary.getByRole('heading', { name: prefix, level: 2, exact: true }).count(), 1)
      assert.equal((await mean.innerText()).trim(), average)
      const details = await summary.locator('.layer-list > div').evaluateAll(nodes => Object.fromEntries(
        nodes.map(node => [node.querySelector('dt').textContent.trim(), node.querySelector('dd').textContent.trim()]),
      ))
      assert.equal(details['/64 blocks with exact observations'], `${observed} / 65536`)
      assert.equal(details['/64 blocks with positive risk'], String(observed))
      assert.equal(await page.getByRole('grid').count(), 0)
      assert.equal(await page.getByRole('gridcell').count(), 0)
    }
  })
  await test('unobserved IPs render a numeric zero without scored evidence', async () => {
    for (const query of ['198.51.100.77', '2001:db8:1::1']) {
      await page.goto(`${base}/ip/quality/?q=${encodeURIComponent(query)}`)
      await page.getByRole('heading', { name: 'No scored observations', exact: true }).waitFor()
      const value = page.getByTestId('observed-risk-value')
      assert.equal(await value.evaluate(node => node.tagName), 'B')
      assert.equal((await value.innerText()).trim(), '0')
      assert.equal(await page.locator('.reason-chip').count(), 0)
      const layers = await page.locator('.quality-layout .layer-list > div').evaluateAll(nodes => Object.fromEntries(
        nodes.map(node => [node.querySelector('dt').textContent.trim(), node.querySelector('dd').textContent.trim()]),
      ))
      assert.deepEqual(layers, { 'Exact IP': '0.00 points', Prefix: '0.00 points', 'ASN context': '0.00 points',
        ...(query.includes(':') ? {} : { '/24 neighbors': '0.00 points' }),
      })
    }
  })
  await test('unknown IPv4 retains 256 unknown cells and a numeric zero mean', async () => {
    await page.goto(`${base}/ip/class-c/?q=198.51.100.77`)
    await page.getByRole('grid').waitFor()
    assert.equal(await page.getByRole('gridcell').count(), 256)
    assert.equal(await page.locator('.ip-grid .observed,.ip-grid .positive').count(), 0)
    const cell = page.getByRole('gridcell', { name: '198.51.100.77, unknown', exact: true })
    await cell.click()
    assert(await page.locator('.cell-detail').getByText('Observed risk 0 / 100', { exact: true }).isVisible())
    assert.equal((await page.getByTestId('subnet-risk-mean').innerText()).trim(), '0 / 100')
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
      assert.equal(await broken.locator('.demo-label, .fact-list, .asn-card').count(), 0)
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
      const noStaleFacts = async () => assert.deepEqual(await late.locator('.fact-list dd').allTextContents(), Array(4).fill('Unknown'))
      await noStaleFacts()
      release()
      await late.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))))
      assert.equal(await late.getByRole('textbox').inputValue(), '8.8.8.8')
      assert.equal(await late.getByRole('alert').count(), 0)
      await noStaleFacts()
    } finally { release(); await isolated.close() }
  })
  assert.deepEqual(report.errors, [], 'Browser runtime errors')
  assert.deepEqual(report.network, [], 'Unexpected third-party network requests')
  report.status = 'passed'
} catch (error) { report.status = 'failed'; report.failure = String(error); process.exitCode = 1 }
finally {
  await writeFile(new URL('../../reports/ui-regression.json', import.meta.url), JSON.stringify(report, null, 2) + '\n')
  await context?.close(); await browser.close()
  console.log(JSON.stringify({ status: report.status, tests: report.tests, errors: report.errors, failure: report.failure }, null, 2))
}
