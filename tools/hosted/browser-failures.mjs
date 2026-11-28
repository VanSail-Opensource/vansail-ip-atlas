// Source-free failure markers. Keep this allowlist in sync with browser_failures.py.
const setup = new Set(['startup','preview-origin','candidate-report','corpus','graph-fixture','accessibility-setup',
  'worker-memory-report','browser-launch','cold-queries','hot-queries','cleanup','report-write','report-validation'])
const samples = new Set(['ui-context','hero','root-redirect','dataset-credits','overview','quality','class-c','asn','bgp',
  'unknown-states','ui-metrics','component-context','component-fixture','component-worker','component-keyboard-pan',
  'component-wheel-zoom','component-route-focus','component-accessibility','component-unknown-ipv4'])
const assetClasses = new Set(['asset-http-status','asset-js-body','asset-atlas-size','asset-atlas-transfer'])
const classes = new Set(['contract','playwright-timeout','runtime','report-validation','unexpected-request',
  'page-exception','asset-accounting','resource-observation','privacy-contract',...assetClasses])
// Only exact Python validator exit codes select a gate class. Raw child
// streams stay ignored. Keep in sync with preview_shards.py and browser_failures.py.
const reportGates = new Map([
  [41,'gate-graph'],[42,'gate-accessibility'],[43,'gate-lcp'],[44,'gate-initial-js'],[45,'gate-cls'],[46,'gate-inp'],
  [47,'gate-population'],[48,'gate-candidate-states'],[49,'gate-unknown-states'],[50,'gate-ipv4'],[51,'gate-synthetic-ipv4'],
  [52,'gate-worker-memory'],[53,'gate-cold-payload'],[54,'gate-hot-lookup'],
])
const gateClasses = new Set(reportGates.values())

export class BrowserContractFailure extends Error {}
export class BrowserAssetFailure extends BrowserContractFailure {
  constructor(classification) {
    super('Static asset accounting failed')
    this.classification=assetClasses.has(classification)?classification:'asset-atlas-transfer'
  }
}

export function browserFailureMarker(phase, sample, classification) {
  if (!setup.has(phase) && !samples.has(phase)) phase = 'startup'
  if (!classes.has(classification) && !(phase === 'report-validation' && gateClasses.has(classification))) classification = 'runtime'
  if (!samples.has(phase) || !Number.isInteger(sample) || sample < 1 || sample > 30) sample = '-'
  // A phase that needs a real sample index may not claim one without it.
  if (samples.has(phase) && sample === '-') phase = 'startup'
  return `ATLAS_BROWSER_FAILURE ${phase} ${sample} ${classification}`
}

export function browserDiagnostics(TimeoutError, emit = line => console.error(line)) {
  let phase = 'startup', sample, deferred = null
  const marker = classification => browserFailureMarker(phase, sample, classification)
  return {
    mark(stage, index) { phase = stage; sample = index },
    fail(error) {
      const classification=error instanceof BrowserAssetFailure && assetClasses.has(error.classification) ? error.classification
        : error instanceof BrowserContractFailure ? 'contract'
        : typeof TimeoutError==='function' && error instanceof TimeoutError ? 'playwright-timeout' : 'runtime'
      emit(marker(classification))
    },
    note(classification) { deferred ??= marker(classification) },
    failedReport(status) {
      const classification = phase === 'report-validation' ? reportGates.get(status) : undefined
      emit(deferred ?? marker(classification ?? 'report-validation'))
    },
  }
}
