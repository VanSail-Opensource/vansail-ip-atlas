// Synthetic measurements only. Missing full-population gates never become passes.
import { chromium } from 'playwright'
import { readFile, mkdir, writeFile } from 'node:fs/promises'
import { gzipSync } from 'node:zlib'
import { cpus, totalmem } from 'node:os'
import { createHash } from 'node:crypto'
import { graph24FPSComparison, localGateResult } from './performance-gates.mjs'

const base = new URL(process.env.ATLAS_PREVIEW_URL ?? 'http://127.0.0.1:4173')
const hosted = !['127.0.0.1', 'localhost', '[::1]'].includes(base.hostname)
if (hosted && (base.protocol !== 'https:' || base.username || base.password || !/^[0-9a-f]{8,64}\.[a-z0-9][a-z0-9-]*\.pages\.dev$/.test(base.host) || base.pathname !== '/' || base.search || base.hash))
  throw new Error('Hosted synthetic measurements require an immutable HTTPS Pages deployment origin')
const HERO_SAMPLES = 20
const QUERY_SAMPLES = 5
const reportPath = new URL(hosted ? '../../reports/performance-preview.json' : '../../reports/performance-local.json', import.meta.url)
const report = {
  scope: hosted ? 'hosted-synthetic-measurements' : 'local-synthetic-measurements', hosted_gate_passed: false, local_absolute_gates_passed: false, status: 'measuring',
  url: base.origin, browser: null, hero: [], cold_queries: [], graph: null, errors: [],
  execution_host: { platform: process.platform, arch: process.arch, node: process.versions.node,
    logical_cpus: cpus().length, cpu: cpus()[0]?.model, memory_bytes: totalmem() },
  contract_input_sha256: {},
  protocol: {
    cold_client_context_per_sample: true, hero_samples: HERO_SAMPLES, query_samples: QUERY_SAMPLES,
    hero_viewport: { width: 390, height: 844, device_scale_factor: 2 },
    mobile_cpu_slowdown: 4, desktop_cpu_slowdown: 1,
    network_rtt_ms: 150, network_down_bits_per_second: 1600000,
    network_up_bits_per_second: 750000, reduced_motion: 'no-preference',
    map_tiles: 'mocked-excluded-from-atlas-byte-accounting',
    initial_js: 'all-unique-JavaScript-responses-before-settled-hero-gzip-level9-conservative',
    atlas_bytes: 'actual-response-body-size-including-pointer-manifest-router-dictionaries-and-shards',
    graph_latency: 'trusted-event-capture-to-second-animation-frame-including-handler-and-paint-opportunity',
    graph_frames: 'requestAnimationFrame-intervals-during-ten-seconds-each-of-trusted-pan-zoom-and-route-focus-input',
    transport: hosted ? 'immutable-Pages-preview-actual-HTTP-response-transport' : 'local-static-server-uncompressed-responses-not-Pages-compression-or-hosted-LCP',
    graph_query: 'AS424240', graph_expected_visible_nodes: 24,
    graph_corpus: 'synthetic-graph24-via3-v1-twelve-linear-routes-24-nodes-23-adjacencies',
    cls_scope: 'cold-hero-navigation-only-full-interaction-script-unmeasured',
    percentile: 'nearest-rank',
  },
  unmeasured: [
    'hosted acceptance and standard-runner RSS/scratch/build budgets',
    'real-source full-dataset capacity and expiry rebuild benchmarks',
    'field INP and full scripted interaction lab INP estimate',
    'CLS over the mandatory complete interaction script',
    'browser allocation counts and peak process/worker RSS',
    'mandatory 30-sample all-width/theme population',
    'cached browser indexed-lookup p95 and Go lookup p95',
  ],
}
try {
  const candidate = JSON.parse(await readFile(new URL('../../reports/static-candidate.json', import.meta.url), 'utf8'))
  if (candidate.status !== 'passed' || candidate.mode !== 'synthetic' ||
      !/^[a-f0-9]{64}$/.test(candidate.candidate_bundle_sha256) || !/^[a-f0-9]{64}$/.test(candidate.release_id))
    throw new Error('Local measurement requires a verified exact synthetic static candidate')
  report.candidate_bundle_sha256 = candidate.candidate_bundle_sha256
  report.release_id = candidate.release_id
  for (const path of ['configs/sources.yaml', 'configs/scoring.yaml', 'configs/tier1.yaml', 'configs/web.yaml',
    'configs/release-approval.yaml', 'fixtures/bin/synthetic-via3.json', 'fixtures/bin/synthetic-graph24-via3.json', 'web/pnpm-lock.yaml', 'tools/hosted/toolchains.json']) {
    const bytes = await readFile(new URL(`../../${path}`, import.meta.url))
    report.contract_input_sha256[path] = createHash('sha256').update(bytes).digest('hex')
  }
} catch (error) {
  report.candidate_bundle_sha256 ??= null
  report.errors.push(String(error))
}

const percentile = (values, p) => {
  if (!values.length || values.some(value => typeof value !== 'number' || !Number.isFinite(value))) return null
  const sorted = [...values].sort((a, b) => a - b)
  return sorted[Math.max(0, Math.ceil(p * sorted.length) - 1)]
}
const summary = values => ({ samples: values.length, p50: percentile(values, .5),
  p95: percentile(values, .95), p99: percentile(values, .99),
  maximum: values.length && values.every(value => typeof value === 'number' && Number.isFinite(value)) ? Math.max(...values) : null })
const within = (value, limit) => value == null ? 'unmeasured' : value < limit ? 'within_limit' : 'over_limit'
const tile = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+j9zEAAAAASUVORK5CYII=', 'base64')
let browser

async function contextForSample(mobile = true) {
  const context = await browser.newContext({ viewport: mobile ? { width: 390, height: 844 } : { width: 1280, height: 900 },
    deviceScaleFactor: mobile ? 2 : 1, reducedMotion: 'no-preference', serviceWorkers: 'block' })
  await context.route('**/*', route => {
    const url = new URL(route.request().url())
    if (url.origin === base.origin) return route.continue()
    if (url.origin === 'https://tile.openstreetmap.org')
      return route.fulfill({ status: 200, contentType: 'image/png', body: tile })
    report.errors.push(`Unexpected external request origin: ${url.origin}`)
    return route.abort('blockedbyclient')
  })
  await context.addInitScript(() => {
    window.__atlasPerformance = { lcp_ms: null, cls: 0, lcp_supported: PerformanceObserver.supportedEntryTypes.includes('largest-contentful-paint'),
      cls_supported: PerformanceObserver.supportedEntryTypes.includes('layout-shift') }
    let first = 0, last = 0, session = 0
    if (window.__atlasPerformance.lcp_supported) {
      new PerformanceObserver(list => {
        for (const entry of list.getEntries()) window.__atlasPerformance.lcp_ms = entry.startTime
      }).observe({ type: 'largest-contentful-paint', buffered: true })
    }
    if (window.__atlasPerformance.cls_supported) {
      new PerformanceObserver(list => {
        for (const entry of list.getEntries()) {
          if (entry.hadRecentInput) continue
          if (entry.startTime - last > 1000 || entry.startTime - first > 5000) { first = entry.startTime; session = 0 }
          last = entry.startTime; session += entry.value
          window.__atlasPerformance.cls = Math.max(window.__atlasPerformance.cls, session)
        }
      }).observe({ type: 'layout-shift', buffered: true })
    }
  })
  const page = await context.newPage()
  page.on('pageerror', error => report.errors.push(error.message))
  const cdp = await context.newCDPSession(page)
  await cdp.send('Network.enable')
  await cdp.send('Network.setCacheDisabled', { cacheDisabled: true })
  await cdp.send('Network.setBypassServiceWorker', { bypass: true })
  await cdp.send('Emulation.setCPUThrottlingRate', { rate: mobile ? 4 : 1 })
  await cdp.send('Network.emulateNetworkConditions', { offline: false, latency: 150,
    downloadThroughput: 1600000 / 8, uploadThroughput: 750000 / 8, connectionType: 'cellular3g' })
  const scripts = new Map(), atlas = [], work = []
  context.on('response', response => {
    const url = new URL(response.url())
    if (url.origin !== base.origin) return
    const isJS = /\.(?:m?js)$/.test(url.pathname)
    const isAtlas = url.pathname.startsWith('/_atlas/')
    if (!isJS && !isAtlas) return
    work.push((async () => {
      const body = await response.body()
      if (response.status() !== 200) throw new Error(`Static response ${response.status()} at ${url.pathname}`)
      if (isJS) scripts.set(url.pathname, { bytes: body.length, gzip_bytes: gzipSync(body, { level: 9 }).length })
      if (isAtlas) {
        const sizes = await response.request().sizes()
        if (!Number.isFinite(sizes.responseBodySize) || sizes.responseBodySize <= 0 || sizes.responseHeadersSize < 0)
          throw new Error(`Atlas wire-byte accounting unavailable at ${url.pathname}`)
        atlas.push({ path: url.pathname, body_bytes: sizes.responseBodySize,
          transfer_bytes_with_headers: sizes.responseBodySize + sizes.responseHeadersSize })
      }
    })().catch(error => report.errors.push(String(error))))
  })
  return { context, page, scripts, atlas, settle: async () => {
    await page.waitForLoadState('networkidle')
    await page.waitForTimeout(250)
    await Promise.all(work)
  } }
}

async function graphLatency(page, selector, event, action) {
  await page.evaluate(({ selector, event }) => {
    const element = document.querySelector(selector)
    if (!element) throw new Error('Missing graph interaction target')
    window.__atlasPaint = new Promise((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error('Graph interaction event was not observed')), 5000)
      element.addEventListener(event, () => {
        const start = performance.now()
        requestAnimationFrame(() => requestAnimationFrame(() => { clearTimeout(timeout); resolve(performance.now() - start) }))
      }, { once: true, capture: true })
    })
  }, { selector, event })
  await action()
  return page.evaluate(() => window.__atlasPaint)
}

async function activeGraphFrames(page, actionName, action) {
  await page.evaluate(() => {
    const state = window.__atlasFrames = { start: performance.now(), times: [], stopped: false }
    const frame = now => {
      if (state.stopped) return
      state.times.push(now)
      requestAnimationFrame(frame)
    }
    requestAnimationFrame(frame)
  })
  const start = performance.now()
  let actions = 0
  while (performance.now() - start < 10000) {
    await action(actions++)
    // Keep the page active and allow a paint between trusted interactions.
    await page.evaluate(() => new Promise(resolve => requestAnimationFrame(resolve)))
  }
  const frames = await page.evaluate(() => {
    const state = window.__atlasFrames
    state.stopped = true
    return { start: state.start, end: performance.now(), times: state.times }
  })
  const intervals = frames.times.slice(1).map((time, index) => time - frames.times[index])
  const elapsed = frames.end - frames.start
  const completeSeconds = Math.floor(elapsed / 1000)
  const framesPerSecond = Array.from({ length: completeSeconds }, (_, index) =>
    frames.times.filter(time => time >= frames.start + index * 1000 && time < frames.start + (index + 1) * 1000).length)
  return { action: actionName, actions, duration_ms: elapsed, frames: frames.times.length,
    average_fps: frames.times.length * 1000 / elapsed, complete_second_fps: framesPerSecond,
    minimum_complete_second_fps: Math.min(...framesPerSecond),
    frame_intervals_ms: intervals, frame_interval_summary_ms: summary(intervals) }
}

try {
  if (report.errors.length) throw new Error('Candidate or contract-input provenance is unavailable')
  browser = await chromium.launch({ channel: 'chrome', headless: true })
  report.browser = browser.version()
  for (let index = 0; index < HERO_SAMPLES; index++) {
    const sample = await contextForSample()
    try {
      await sample.page.goto(new URL('/ip/', base).href, { waitUntil: 'networkidle', timeout: 30000 })
      await sample.page.getByRole('textbox', { name: 'IP address or ASN' }).waitFor()
      await sample.settle()
      const metric = await sample.page.evaluate(() => window.__atlasPerformance)
      report.hero.push({ sample: index + 1, ...metric, initial_js_gzip_bytes: [...sample.scripts.values()].reduce((sum, item) => sum + item.gzip_bytes, 0),
        js_files: sample.scripts.size, atlas_requests: sample.atlas.length })
    } finally { await sample.context.close() }
    if ((index + 1) % 5 === 0) console.log(`Local hero samples: ${index + 1}/${HERO_SAMPLES}`)
  }
  for (let index = 0; index < QUERY_SAMPLES; index++) {
    const sample = await contextForSample()
    try {
      await sample.page.goto(new URL('/ip/overview/?q=203.0.113.1', base).href, { waitUntil: 'networkidle', timeout: 30000 })
      await sample.page.locator('.demo-label').waitFor({ timeout: 30000 })
      await sample.settle()
      if (sample.atlas.length < 3) throw new Error('Cold query byte accounting did not observe its control and object requests')
      report.cold_queries.push({ sample: index + 1, objects_and_controls: sample.atlas.length,
        atlas_body_bytes: sample.atlas.reduce((sum, item) => sum + item.body_bytes, 0),
        transfer_bytes_with_headers: sample.atlas.reduce((sum, item) => sum + item.transfer_bytes_with_headers, 0),
        responses: sample.atlas })
    } finally { await sample.context.close() }
  }
  console.log('Local cold query samples complete; measuring graph interactions')
  const graph = await contextForSample(false)
  try {
    await graph.page.goto(new URL('/ip/bgp/?q=AS424240', base).href, { waitUntil: 'networkidle', timeout: 30000 })
    await graph.page.locator('.bgp-graph svg').waitFor({ timeout: 30000 })
    if (await graph.page.locator('.graph-node').count() !== 24) throw new Error('The artificial AS424240 graph must contain exactly 24 visible nodes')
    const focus = graph.page.getByRole('combobox', { name: 'Focus observed route' })
    const routeCount = await focus.locator('option').count()
    if (routeCount !== 13) throw new Error('The graph fixture must retain all 12 routes plus all-routes focus')
    const focusKey = index => index % (2 * (routeCount - 1)) < routeCount - 1 ? 'ArrowDown' : 'ArrowUp'
    const layoutBefore = await graph.page.locator('.graph-node').evaluateAll(nodes => nodes.map(node => node.getAttribute('transform')))
    const svg = graph.page.locator('.bgp-graph svg')
    await svg.focus()
    const latencies = []
    for (let index = 0; index < 20; index++) {
      await svg.focus()
      latencies.push({ action: 'keyboard-pan', ms: await graphLatency(graph.page, '.bgp-graph svg', 'keydown', () => graph.page.keyboard.press(index % 2 ? 'ArrowLeft' : 'ArrowRight')) })
      const bounds = await svg.boundingBox()
      await graph.page.mouse.move(bounds.x + bounds.width / 2, bounds.y + bounds.height / 2)
      latencies.push({ action: 'wheel-zoom', ms: await graphLatency(graph.page, '.bgp-graph svg', 'wheel', () => graph.page.mouse.wheel(0, index % 2 ? 50 : -50)) })
      await focus.focus()
      latencies.push({ action: 'route-focus', ms: await graphLatency(graph.page, '.graph-toolbar select', 'change', () => graph.page.keyboard.press(focusKey(index))) })
    }
    console.log('Local graph event-to-paint samples complete; measuring active frame intervals')
    await svg.focus()
    const activeFrames = [await activeGraphFrames(graph.page, 'keyboard-pan', index => graph.page.keyboard.press(index % 2 ? 'ArrowLeft' : 'ArrowRight'))]
    const bounds = await svg.boundingBox()
    await graph.page.mouse.move(bounds.x + bounds.width / 2, bounds.y + bounds.height / 2)
    activeFrames.push(await activeGraphFrames(graph.page, 'wheel-zoom', index => graph.page.mouse.wheel(0, index % 2 ? 50 : -50)))
    if (routeCount > 1) {
      await focus.focus()
      await focus.selectOption('-1')
      activeFrames.push(await activeGraphFrames(graph.page, 'route-focus', index => graph.page.keyboard.press(focusKey(index))))
    }
    const layoutAfter = await graph.page.locator('.graph-node').evaluateAll(nodes => nodes.map(node => node.getAttribute('transform')))
    if (JSON.stringify(layoutBefore) !== JSON.stringify(layoutAfter)) throw new Error('Route focus changed the graph layout')
    report.graph = { visible_nodes: await graph.page.locator('.graph-node').count(), interactions: latencies,
      event_to_paint_ms: summary(latencies.map(value => value.ms)), active_frames: activeFrames,
      query: 'AS424240', corpus: report.protocol.graph_corpus, synthetic: true,
      route_focus_options: routeCount, worst_case_24_nodes: 'measured-synthetic-single-desktop-context', field_INP: 'unmeasured' }
  } finally { await graph.context.close() }
  const lcp = summary(report.hero.map(value => value.lcp_ms))
  const cls = summary(report.hero.map(value => value.cls_supported ? value.cls : null))
  const js = summary(report.hero.map(value => value.initial_js_gzip_bytes))
  const atlas = summary(report.cold_queries.map(value => value.atlas_body_bytes))
  report.summary = { lcp_ms: lcp, cls, initial_js_gzip_bytes: js, cold_atlas_body_bytes: atlas,
    local_comparisons: { lcp: within(lcp.p95, 2500), cls: within(cls.p95, .1), initial_js: within(js.p95, 200 * 1024),
      cold_atlas_payload: within(atlas.p95, 400 * 1024), graph_50fps_at_24_nodes: graph24FPSComparison(report.graph),
      full_interaction_INP: 'unmeasured', complete_interaction_CLS: 'unmeasured', browser_peak_memory: 'unmeasured',
      mandatory_theme_viewport_population: 'unmeasured', full_dataset_hosted_capacity: 'unmeasured' } }
  const gates = localGateResult(report.summary.local_comparisons, report.errors)
  const { exit_code, ...gateReport } = gates
  Object.assign(report, gateReport)
  if (exit_code) process.exitCode = exit_code
} catch (error) {
  report.status = 'measurement-errors'; report.errors.push(String(error)); process.exitCode = 1
} finally {
  await browser?.close()
  await mkdir(new URL('.', reportPath), { recursive: true })
  await writeFile(reportPath, JSON.stringify(report, null, 2) + '\n')
  console.log(JSON.stringify({ status: report.status, local_absolute_gates_passed: report.local_absolute_gates_passed,
    measured_local_comparisons_passed: report.measured_local_comparisons_passed,
    browser: report.browser, summary: report.summary, errors: report.errors }, null, 2))
}
