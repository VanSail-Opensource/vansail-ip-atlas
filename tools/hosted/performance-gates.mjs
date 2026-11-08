/** Reporting only: absent measurements never satisfy an absolute gate. */
export function localGateResult(comparisons, errors = []) {
  const entries = Object.entries(comparisons)
  if (entries.some(([, value]) => !['within_limit', 'over_limit', 'unmeasured'].includes(value)))
    throw new Error('Unknown performance comparison state')
  const failed = entries.filter(([, value]) => value === 'over_limit').map(([name]) => name)
  const pending = entries.filter(([, value]) => value === 'unmeasured').map(([name]) => name)
  const measured = entries.length - pending.length
  return {
    local_absolute_gates_passed: errors.length === 0 && measured > 0 && failed.length === 0 && pending.length === 0,
    measured_local_comparisons_passed: errors.length === 0 && measured > 0 && failed.length === 0,
    failed_local_gates: failed,
    unmeasured_local_gates: pending,
    status: errors.length ? 'measurement-errors' : failed.length ? 'measured-with-budget-failures'
      : pending.length ? 'measured-with-unmeasured-gates' : 'measured',
    exit_code: errors.length || failed.length ? 1 : 0,
  }
}

/** A measured 24-node graph needs every mandatory active action and full seconds. */
export function graph24FPSComparison(graph) {
  if (graph?.visible_nodes !== 24) return 'unmeasured'
  const actions = ['keyboard-pan', 'wheel-zoom', 'route-focus']
  const rows = actions.map(action => graph.active_frames?.find(row => row.action === action))
  if (rows.some(row => !row || row.actions < 1 || row.duration_ms < 10000 ||
      !Array.isArray(row.complete_second_fps) || row.complete_second_fps.length < 10 ||
      row.complete_second_fps.some(value => !Number.isFinite(value) || value < 0))) return 'unmeasured'
  return rows.every(row => row.complete_second_fps.every(value => value >= 50)) ? 'within_limit' : 'over_limit'
}

/** Count full circles inside both the SVG and its actual visible screen clip. */
export function graphVisibleNodeCount(sample) {
  const valid = box => box && ['left','right','top','bottom'].every(key => Number.isFinite(box[key])) && box.right > box.left && box.bottom > box.top
  if (!Array.isArray(sample?.circles) || !valid(sample.svg_bounds) || !valid(sample.visible_bounds)) return 0
  return sample.circles.filter(box => valid(box) && [sample.svg_bounds,sample.visible_bounds].every(bounds =>
    box.left >= bounds.left && box.right <= bounds.right && box.top >= bounds.top && box.bottom <= bounds.bottom)).length
}
