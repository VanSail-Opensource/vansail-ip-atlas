import { chromium } from 'playwright'
import { readFile, mkdir, writeFile } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import { pathToFileURL } from 'node:url'
import { resolve } from 'node:path'

const corpus = JSON.parse(await readFile(new URL('./fixtures/zstd.json', import.meta.url), 'utf8'))
const reportPath = process.env.ATLAS_CODEC_REPORT
  ? pathToFileURL(resolve(process.env.ATLAS_CODEC_REPORT))
  : new URL('../../reports/codec.json', import.meta.url)
const report = { contract: 'C06', status: 'failed', mode: 'synthetic', browser: null, cases: [] }
let browser
try {
  // The chrome channel uses branded Google Chrome stable, never bundled Chromium.
  browser = await chromium.launch({ channel: 'chrome', headless: true })
  report.browser = browser.version()
  const context = await browser.newContext()
  const page = await context.newPage()
  await page.route('https://atlas.invalid/**', route => route.fulfill({
    status: 200, contentType: 'text/html', body: '<!doctype html><title>Codec contract</title>',
  }))
  // A fulfilled HTTPS test origin provides Web Crypto; no request leaves Chrome.
  await page.goto('https://atlas.invalid/')
  report.user_agent = await page.evaluate(() => navigator.userAgent)
  report.corpus_sha256 = createHash('sha256').update(JSON.stringify(corpus)).digest('hex')
  const results = await page.evaluate(async (vectors) => {
    const results = []
    const sha = async (bytes) => [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))]
      .map(n => n.toString(16).padStart(2, '0')).join('')
    async function decode(input, limit) {
      const reader = new Blob([input]).stream().pipeThrough(new DecompressionStream('zstd')).getReader()
      const chunks = []
      let total = 0
      try {
        while (true) {
          const { done, value } = await reader.read()
          if (done) break
          total += value.byteLength
          if (total > limit) {
            await reader.cancel('output limit')
            throw new Error('output-limit')
          }
          chunks.push(value)
        }
      } finally { reader.releaseLock() }
      const bytes = new Uint8Array(total)
      let offset = 0
      for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length }
      return bytes
    }
    for (const vector of vectors) {
      try {
        const encoded = Uint8Array.from(atob(vector.encoded_base64), ch => ch.charCodeAt(0))
        const decoded = await decode(encoded, vector.decoded_bytes)
        const hash = await sha(decoded)
        if (decoded.length !== vector.decoded_bytes || hash !== vector.decoded_sha256) throw new Error('golden-mismatch')
        results.push({ name: vector.name, status: 'passed', decoded_bytes: decoded.length })
        if (vector.decoded_bytes > 0) {
          let rejected = false
          try { await decode(encoded, vector.decoded_bytes - 1) }
          catch (error) { rejected = error.message === 'output-limit' }
          if (!rejected) throw new Error('bound-not-enforced')
          results.push({ name: `${vector.name}-output-bound`, status: 'passed' })
        }
        let rejected = false
        try { await decode(encoded.slice(0, Math.max(1, encoded.length - 2)), vector.decoded_bytes) }
        catch { rejected = true }
        if (!rejected) throw new Error('truncation-not-rejected')
        results.push({ name: `${vector.name}-truncated`, status: 'passed' })
      } catch (error) {
        results.push({ name: vector.name, status: 'failed', error: String(error) })
      }
    }
    return results
  }, corpus)
  report.cases = results
  report.status = results.every(result => result.status === 'passed') ? 'passed' : 'failed'
  // These are codec acceptance tests. VIA3/parser parity and memory-high-water
  // acceptance remain separate mandatory gates, not implied by this result.
} catch (error) {
  report.error = String(error)
} finally {
  await browser?.close()
  await mkdir(new URL('.', reportPath), { recursive: true })
  await writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`)
}
console.log(`C06 native Zstandard: ${report.status}; Chrome ${report.browser ?? 'unavailable'}`)
if (report.status !== 'passed') process.exitCode = 1
