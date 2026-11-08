import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { parseCreditIndex, parseCreditDocument, loadDatasetCredits } from '../app/lib/datasetCredits.ts'

const id = 'a'.repeat(64)
const encoder = new TextEncoder()
const canonical = (v: unknown): string => Array.isArray(v) ? `[${v.map(canonical).join(',')}]` : v && typeof v === 'object' ? `{${Object.keys(v).sort().map(k => `${JSON.stringify(k)}:${canonical((v as Record<string, unknown>)[k])}`).join(',')}}` : JSON.stringify(v)
const bytes = (v: unknown) => encoder.encode(canonical(v))
const entry = { name: 'Example geography', text: 'Attribution for an included dataset.', url: 'https://example.org/data', license_url: 'https://example.org/license' }

test('Go, Python and browser accept the same reviewed credit URL corpus', () => {
  const corpus = JSON.parse(readFileSync(new URL('../../fixtures/contracts/attribution-urls-v1.json', import.meta.url), 'utf8'))
  for (const row of corpus.cases) {
    const parse = () => parseCreditDocument(bytes({ format_version: 1, release_id: id, mode: 'production', entries: [{ ...entry, url: row.url }] }), id)
    if (row.valid) assert.doesNotThrow(parse, row.url)
    else assert.throws(parse, row.url)
  }
})

test('shared credit text is plain Unicode data and never credentials or executable markup', () => {
  const corpus = JSON.parse(readFileSync(new URL('../../fixtures/contracts/attribution-text-v1.json', import.meta.url), 'utf8'))
  for (const row of corpus.cases) {
    const parse = () => parseCreditDocument(bytes({ format_version: 1, release_id: id, mode: 'production', entries: [{ ...entry, text: row.text }] }), id)
    if (row.valid) assert.doesNotThrow(parse)
    else assert.throws(parse)
  }
})

test('credits have a closed global schema and cannot claim real datasets in synthetic mode', () => {
  assert.deepEqual(parseCreditDocument(bytes({ format_version: 1, release_id: id, mode: 'production', entries: [entry] }), id).entries, [entry])
  for (const mutation of [ { ...entry, source_id: 'private' }, { ...entry, url: 'https://127.0.0.1' }, { ...entry, url: 'https://user:secret@example.org' }, { ...entry, text: 'hidden\u202esecret' }, { ...entry, url: 'https://example.org?token=secret' } ])
    assert.throws(() => parseCreditDocument(bytes({ format_version: 1, release_id: id, mode: 'production', entries: [mutation] }), id))
  assert.throws(() => parseCreditDocument(bytes({ format_version: 1, release_id: id, mode: 'synthetic', entries: [entry] }), id))
  assert.throws(() => parseCreditDocument(encoder.encode(`{"entries":[],"entries":[],"format_version":1,"mode":"synthetic","release_id":"${id}"}`), id))
})

test('credit index pins content-addressed documents and rejects unrelated or duplicate releases', () => {
  const hash = 'b'.repeat(64)
  const index = { format_version: 1, current_release_id: id, releases: [{ release_id: id, credits_path: `/_atlas/credits/${hash}.json`, credits_sha256: hash }] }
  assert.equal(parseCreditIndex(bytes(index)).current_release_id, id)
  assert.throws(() => parseCreditIndex(bytes({ ...index, current_release_id: 'c'.repeat(64) })))
  assert.throws(() => parseCreditIndex(bytes({ ...index, releases: [...index.releases, ...index.releases] })))
  assert.throws(() => parseCreditIndex(bytes({ ...index, releases: [{ ...index.releases[0], credits_path: '/private.json?q=1' }] })))
})

test('only opening credits fetches shared metadata without any query or external origin', async () => {
  const document = bytes({ format_version: 1, release_id: id, mode: 'synthetic', entries: [] })
  const hash = Buffer.from(await crypto.subtle.digest('SHA-256', document)).toString('hex')
  const index = bytes({ format_version: 1, current_release_id: id, releases: [{ release_id: id, credits_path: `/_atlas/credits/${hash}.json`, credits_sha256: hash }] })
  const seen: string[] = []
  const fetcher = async (path: string) => { seen.push(path); return new Response(path === '/dataset-credits.json' ? index : document) }
  const result = await loadDatasetCredits(undefined, undefined, fetcher as typeof fetch)
  assert.equal(result.mode, 'synthetic')
  assert.deepEqual(seen, ['/dataset-credits.json', `/_atlas/credits/${hash}.json`])
  await assert.rejects(loadDatasetCredits('c'.repeat(64), undefined, fetcher as typeof fetch))
  await assert.rejects(loadDatasetCredits(undefined, undefined, (async (path: string) => new Response(path === '/dataset-credits.json' ? index : encoder.encode('{}'))) as typeof fetch))
})

test('cancelled and oversized credit requests cannot expose metadata or continue fetching', async () => {
  const controller = new AbortController(); controller.abort()
  let requests = 0
  await assert.rejects(loadDatasetCredits(undefined, controller.signal, (async () => { requests++; return new Response('{}') }) as typeof fetch))
  assert.equal(requests, 0)
  await assert.rejects(loadDatasetCredits(undefined, undefined, (async () => new Response(new Uint8Array(8193))) as typeof fetch))
  const document = { format_version: 1, release_id: id, mode: 'production', entries: [entry, { ...entry, text: 'Different required notice.' }] }
  document.entries.sort((a, b) => canonical(a) < canonical(b) ? -1 : 1)
  assert.equal(parseCreditDocument(bytes(document), id).entries.length, 2)
})
