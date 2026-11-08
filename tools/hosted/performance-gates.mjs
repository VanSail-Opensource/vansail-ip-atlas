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
