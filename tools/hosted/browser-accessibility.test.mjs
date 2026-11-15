import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { test } from 'node:test'
import { runInNewContext } from 'node:vm'
import { auditAccessibility } from './browser-accessibility.mjs'

async function emit(result) {
  const document = {}, calls = []
  const page = { async evaluate(value) {
    calls.push(value)
    if (typeof value === 'string') return
    return runInNewContext(`(${value.toString()})()`, { document, window: { axe: { async run(root, options) {
      assert.equal(root, document)
      assert.deepEqual(JSON.parse(JSON.stringify(options)), { runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21aa'] } })
      return result
    } } } })
  } }
  const report = await auditAccessibility(page, 'isolated axe source fixture')
  assert.equal(calls.length, 2)
  assert.equal(calls[0], 'isolated axe source fixture')
  return JSON.parse(JSON.stringify(report))
}

test('the shared browser emitter preserves actual engine identity and every finding count', async () => {
  const result = {
    testEngine: { name: 'axe-core', version: 'fixture-observed-version' },
    violations: [{ id: 'color-contrast', impact: 'serious', nodes: [{}, {}] }, { id: 'label', impact: 'critical', nodes: [{}] }],
    incomplete: [{ id: 'color-contrast', nodes: [{}, {}, {}] }, { id: 'image-alt', nodes: [{}] }],
  }
  assert.deepEqual(await emit(result), {
    engine: 'axe-core', version: 'fixture-observed-version',
    violations: [{ id: 'color-contrast', impact: 'serious', nodes: 2 }, { id: 'label', impact: 'critical', nodes: 1 }],
    incomplete: [{ id: 'color-contrast', nodes: 3 }, { id: 'image-alt', nodes: 1 }],
  })
})

test('actual component emitter output satisfies acceptance only with measured clean axe results', async () => {
  const clean = { testEngine: { name: 'axe-core', version: '4.14.0' }, violations: [], incomplete: [] }
  const emitted = await Promise.all([
    emit(clean),
    emit({ ...clean, testEngine: { version: '4.14.0' } }),
    emit({ ...clean, violations: [{ id: 'color-contrast', impact: 'serious', nodes: [{}] }] }),
    emit({ ...clean, incomplete: [{ id: 'color-contrast', nodes: [{}] }] }),
  ])
  const checked = spawnSync('python3', ['-c', `
import json, sys
from tools.release_contract.acceptance import browser_gates
from tools.release_contract.test_acceptance import browser_report
results = []
for emitted in json.load(sys.stdin):
    report = browser_report()
    for width in (320, 390, 1280, 1440):
        for theme in ('light', 'dark'):
            for sample in range(1, 31):
                identity = {'width': width, 'theme': theme, 'sample': sample}
                report['populations'].append({**identity, 'accessibility': {'engine': 'axe-core', 'violations': [], 'incomplete': []}})
                report['component_populations'].append({**identity, 'accessibility': emitted})
    results.append({key: value for key, value in browser_gates(report).items() if key.endswith('_accessibility')})
print(json.dumps(results))
`], { cwd: new URL('../../', import.meta.url), input: JSON.stringify(emitted), encoding: 'utf8' })
  assert.equal(checked.status, 0, checked.stderr)
  const results = JSON.parse(checked.stdout)
  for (const [index, expected] of ['passed', 'unmeasured', 'failed', 'unmeasured'].entries()) {
    assert.equal(Object.keys(results[index]).length, 8)
    assert.deepEqual(new Set(Object.values(results[index])), new Set([expected]))
  }
})
