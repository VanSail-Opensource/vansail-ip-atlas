import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { bundleLicenseAudit, installedPackage } from './bundle_licenses.ts'

test('private audit binds client and worker module ancestry to exact emitted bytes', () => {
  const root = mkdtempSync(join(tmpdir(), 'atlas-bundle-audit-'))
  try {
    const path = join(root, 'web/node_modules/@example/runtime')
    mkdirSync(path, { recursive: true })
    writeFileSync(join(path, 'package.json'), JSON.stringify({ name: '@example/runtime', version: '1.2.3' }))
    const id = join(path, 'index.js')
    assert.deepEqual(installedPackage(id, root), { name: '@example/runtime', version: '1.2.3' })
    const audit = bundleLicenseAudit(root)
    audit.client.configResolved({ build: {} }); audit.client.buildStart()
    const worker = audit.workers()[0]
    worker.configResolved({ build: {} })
    const context = { *getModuleIds() { yield id }, getModuleInfo() { return { importedIds: [], dynamicallyImportedIds: [] } } }
    worker.generateBundle.call(context, {}, { worker: { type: 'chunk', fileName: 'worker.js', code: 'export{}', modules: { [id]: { renderedLength: 8 } } } })
    audit.client.writeBundle.call(context, {}, { worker: { type: 'asset', fileName: 'worker.js', source: 'export{}' }, entry: { type: 'chunk', fileName: 'entry.js', code: 'import("./worker.js")', modules: {} } })
    const report = JSON.parse(readFileSync(join(root, 'build-private/software-bundle-audit.json'), 'utf8'))
    assert.equal(report.workers[0].modules[0].package, '@example/runtime')
    assert.equal(report.workers[0].modules[0].version, '1.2.3')
    assert.equal(report.client.assets.length, 2)
    assert.equal(report.workers[0].modules[0].id.startsWith(root), false)
    assert.throws(() => audit.client.writeBundle.call(context, {}, { entry: { type: 'chunk', fileName: 'entry.js', code: 'no worker', modules: {} } }), /not bound/)
  } finally { rmSync(root, { recursive: true, force: true }) }
})

test('SSR output cannot replace the client audit and packages cannot escape the module tree', () => {
  const root = mkdtempSync(join(tmpdir(), 'atlas-bundle-audit-'))
  try {
    const audit = bundleLicenseAudit(root)
    audit.client.configResolved({ build: { ssr: true } })
    audit.client.writeBundle.call({ *getModuleIds() {} }, {}, {})
    assert.throws(() => readFileSync(join(root, 'build-private/software-bundle-audit.json')), /ENOENT/)
    assert.equal(installedPackage('virtual:nuxt:entry', root), null)
    assert.throws(() => installedPackage(join(tmpdir(), 'outside/node_modules/pkg/index.js'), root), /escaped/)
  } finally { rmSync(root, { recursive: true, force: true }) }
})
