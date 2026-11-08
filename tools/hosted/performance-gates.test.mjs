import assert from 'node:assert/strict'
import { test } from 'node:test'
import { graph24FPSComparison, localGateResult } from './performance-gates.mjs'

test('an actual budget failure makes the measurement process fail', () => {
  const result = localGateResult({ lcp: 'over_limit', cls: 'within_limit' })
  assert.equal(result.exit_code, 1)
  assert.equal(result.local_absolute_gates_passed, false)
  assert.equal(result.measured_local_comparisons_passed, false)
  assert.deepEqual(result.failed_local_gates, ['lcp'])
  assert.equal(result.status, 'measured-with-budget-failures')
})

test('a complete measured population may pass its local comparisons', () => {
  const result = localGateResult({ lcp: 'within_limit', cls: 'within_limit' })
  assert.equal(result.exit_code, 0)
  assert.equal(result.local_absolute_gates_passed, true)
  assert.equal(result.measured_local_comparisons_passed, true)
})

test('unknown and empty populations cannot become passing absolute gates', () => {
  const result = localGateResult({ lcp: 'within_limit', graph: 'unmeasured' })
  assert.equal(result.local_absolute_gates_passed, false)
  assert.equal(result.measured_local_comparisons_passed, true)
  assert.deepEqual(result.unmeasured_local_gates, ['graph'])
  assert.equal(result.status, 'measured-with-unmeasured-gates')
  assert.equal(localGateResult({}).local_absolute_gates_passed, false)
  assert.equal(localGateResult({ graph: 'unmeasured' }).measured_local_comparisons_passed, false)
})

test('runtime errors and invalid comparison labels cannot mask a failed measurement', () => {
  const result = localGateResult({ lcp: 'within_limit' }, ['failed response'])
  assert.equal(result.exit_code, 1)
  assert.equal(result.local_absolute_gates_passed, false)
  assert.equal(result.measured_local_comparisons_passed, false)
  assert.equal(result.status, 'measurement-errors')
  assert.throws(() => localGateResult({ lcp: 'probably fine' }), /Unknown performance/)
})

test('24-node FPS gate requires complete active pan/zoom/focus measurements', () => {
  const graph = { visible_nodes: 24, active_frames: ['keyboard-pan', 'wheel-zoom', 'route-focus'].map(action =>
    ({ action, actions: 100, duration_ms: 10001, complete_second_fps: Array(10).fill(50) })) }
  assert.equal(graph24FPSComparison(graph), 'within_limit')
  assert.equal(graph24FPSComparison({ ...graph, visible_nodes: 3 }), 'unmeasured')
  assert.equal(graph24FPSComparison({ ...graph, active_frames: graph.active_frames.slice(0, 2) }), 'unmeasured')
  graph.active_frames[1].complete_second_fps[4] = 49
  graph.diagnostic_variants_not_acceptance = [{ acceptance_eligible: false,
    samples: graph.active_frames.map(row => ({ ...row, complete_second_fps: Array(10).fill(240) })) }]
  assert.equal(graph24FPSComparison(graph), 'over_limit')
  graph.active_frames[1].complete_second_fps[4] = NaN
  assert.equal(graph24FPSComparison(graph), 'unmeasured')
})
