// Source-free failure markers. Keep this allowlist in sync with browser_failures.py.
const setup = new Set(['startup','preview-origin','candidate-report','corpus','graph-fixture','accessibility-setup',
  'worker-memory-report','browser-launch','cold-queries','hot-queries','cleanup','report-write','report-validation'])
const samples = new Set(['ui-context','hero','root-redirect','dataset-credits','overview','quality','class-c','asn','bgp',
  'unknown-states','ui-metrics','component-context','component-fixture','component-worker','component-keyboard-pan',
  'component-wheel-zoom','component-route-focus','component-accessibility','component-unknown-ipv4'])
const classes = new Set(['contract','playwright-timeout','runtime','report-validation','unexpected-request',
  'page-exception','asset-accounting','resource-observation','privacy-contract'])

export class BrowserContractFailure extends Error {}

export function browserFailureMarker(phase, sample, classification) {
  if (!setup.has(phase) && !samples.has(phase)) phase = 'startup'
  if (!classes.has(classification)) classification = 'runtime'
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
      const classification=error instanceof BrowserContractFailure ? 'contract'
        : typeof TimeoutError==='function' && error instanceof TimeoutError ? 'playwright-timeout' : 'runtime'
      emit(marker(classification))
    },
    note(classification) { deferred ??= marker(classification) },
    failedReport() { emit(deferred ?? marker('report-validation')) },
  }
}
