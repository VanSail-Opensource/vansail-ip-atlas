import { chromium } from 'playwright'
import { readFile, mkdir, writeFile } from 'node:fs/promises'
import { stripTypeScriptTypes } from 'node:module'
import { createHash } from 'node:crypto'
import { pathToFileURL } from 'node:url'
import { resolve } from 'node:path'

const corpus = JSON.parse(await readFile(new URL('./fixtures/zstd.json', import.meta.url), 'utf8'))
const wrapper = await readFile(new URL('../../web/app/lib/zstd.ts', import.meta.url), 'utf8')
const library = await readFile(new URL('../../web/node_modules/fzstd/esm/index.mjs', import.meta.url), 'utf8')
// The test bundle contains exactly the pinned local dependency and the product
// wrapper. Nuxt independently packages the same imports for the static app.
const bundle = library + '\n' + stripTypeScriptTypes(wrapper, { mode: 'strip' })
  .replace(/^import \{ Decompress \} from ['"]fzstd['"];?\r?\n/m, '')
const path = process.env.ATLAS_CODEC_REPORT
  ? pathToFileURL(resolve(process.env.ATLAS_CODEC_REPORT))
  : new URL('../../reports/codec-bundled.json', import.meta.url)
const report = { contract: 'C06-amendment-2026-11-08', decoder: 'fzstd@0.1.1', mode: 'synthetic',
  status: 'failed', browser: null, node: process.versions.node, bundle_sha256: createHash('sha256').update(bundle).digest('hex'), cases: [] }
let browser
try {
  browser = await chromium.launch({ channel: 'chrome', headless: true })
  report.browser = browser.version()
  const context = await browser.newContext()
  const page = await context.newPage()
  await page.route('https://atlas.invalid/**', (route) => {
    const module = route.request().url().endsWith('/decoder.js')
    return route.fulfill({ status: 200, contentType: module ? 'text/javascript' : 'text/html',
      body: module ? bundle : '<!doctype html><title>Bundled codec contract</title>' })
  })
  await page.goto('https://atlas.invalid/')
  report.user_agent = await page.evaluate(() => navigator.userAgent)
  report.cases = await page.evaluate(async vectors => {
    const { decodeZstd, inspectZstdFrame } = await import('/decoder.js')
    const results = []
    async function check(name, callback) {
      try { await callback(); results.push({ name, status: 'passed' }) }
      catch (error) { results.push({ name, status: 'failed', error: String(error) }) }
    }
    const toBytes = vector => Uint8Array.from(atob(vector.encoded_base64), value => value.charCodeAt(0))
    async function rejects(input, length, code) {
      try { await decodeZstd(input, length) }
      catch (error) { if (!code || error.code === code) return; throw error }
      throw new Error('Malformed frame accepted')
    }
    for (const vector of vectors) {
      await check(vector.name, async () => {
        const decoded = await decodeZstd(toBytes(vector), vector.decoded_bytes)
        const hash = [...new Uint8Array(await crypto.subtle.digest('SHA-256', decoded))]
          .map(value => value.toString(16).padStart(2, '0')).join('')
        if (hash !== vector.decoded_sha256 || decoded.length !== vector.decoded_bytes) throw new Error('Golden mismatch')
      })
      await check(`${vector.name}-truncated`, () => rejects(toBytes(vector).slice(0, -1), vector.decoded_bytes))
      const changed = toBytes(vector); changed[changed.length - 1] ^= 1
      await check(`${vector.name}-checksum`, () => rejects(changed, vector.decoded_bytes, 'integrity'))
    }
    await check('window-bomb-before-allocation', async () => {
      const bomb = new Uint8Array([0x28, 0xb5, 0x2f, 0xfd, 0x84, 0xf8, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0])
      try { inspectZstdFrame(bomb, 1) }
      catch (error) { if (error.code === 'limit') return; throw error }
      throw new Error('Unbounded window accepted')
    })
    await check('emitted-output-guard', async () => {
      const original = toBytes(vectors[2])
      const forged = new Uint8Array(original.length + 1)
      forged.set([0x28, 0xb5, 0x2f, 0xfd, 0x84, 0x68, 16, 0, 0, 0])
      forged.set(original.subarray(9), 10)
      inspectZstdFrame(forged, 16)
      await rejects(forged, 16, 'limit')
    })
    await check('concat-rejected', async () => {
      const original = toBytes(vectors[1]), concat = new Uint8Array(original.length * 2)
      concat.set(original); concat.set(original, original.length)
      await rejects(concat, vectors[1].decoded_bytes, 'input')
    })
    return results
  }, corpus)
  report.status = report.cases.every(value => value.status === 'passed') ? 'passed' : 'failed'
} catch (error) { report.error = String(error) }
finally {
  await browser?.close()
  await mkdir(new URL('.', path), { recursive: true })
  await writeFile(path, `${JSON.stringify(report, null, 2)}\n`)
}
console.log(`C06 bundled Zstandard: ${report.status}; Chrome ${report.browser ?? 'unavailable'}`)
if (report.status !== 'passed') process.exitCode = 1
