import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import { AtlasReader, parseShard, hash } from '../../web/app/workers/atlas.ts'

const golden = JSON.parse(readFileSync(new URL('../../fixtures/bin/synthetic-via3.json', import.meta.url), 'utf8'))
const canonical = value => JSON.stringify(value, Object.keys(value).sort())
const stable = value => value === null || typeof value !== 'object' ? JSON.stringify(value) : Array.isArray(value) ? `[${value.map(stable).join(',')}]` : `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${stable(value[key])}`).join(',')}}`
const files = new Map(golden.objects.map(object => [`/_atlas/objects/${object.info.sha256}.via3`, new Uint8Array(Buffer.from(object.base64, 'base64'))]))
files.set('/_atlas/current.json', new TextEncoder().encode(canonical(golden.pointer)))
files.set(golden.pointer.manifest_path, new TextEncoder().encode(stable(golden.manifest)))
const response = (path, options) => {
  if (options?.signal?.aborted) throw new DOMException('Aborted', 'AbortError')
  const bytes = files.get(path)
  return Promise.resolve(new Response(bytes, { status: bytes ? 200 : 404, headers: { 'content-length': String(bytes?.length ?? 0) } }))
}

test('every frozen VIA3 shard kind decodes its Go-produced compressed bytes', async () => {
  const kinds = new Set()
  for (const object of golden.objects) {
    const shard = await parseShard(new Uint8Array(Buffer.from(object.base64, 'base64')))
    assert.equal(shard.kind, object.info.kind)
    kinds.add(shard.kind)
  }
  assert.deepEqual([...kinds].sort((a, b) => a - b), Array.from({ length: 14 }, (_, index) => index + 1))
})

test('RPKI uses the selected announcement and origin despite unrelated more-specific rows', async () => {
  const fixture = JSON.parse(readFileSync(new URL('../../fixtures/bin/rpki-prefix-lookup.json', import.meta.url), 'utf8'))
  const shard = await parseShard(new Uint8Array(Buffer.from(fixture.base64, 'base64')))
  for (const item of fixture.cases) {
    const row = shard.rpki(item.ip, item.origin, item.announcement || null)
    assert.equal(row ? row[8] : -1, item.status, `${item.ip} AS${item.origin} announcement ${item.announcement}`)
  }
})

test('Go and worker canonical lookup answers match exactly', async t => {
  const reader = new AtlasReader(response, () => golden.clock)
  for (const vector of golden.vectors) {
    await t.test(vector.q, async () => {
      assert.deepEqual(await reader.lookup(vector.q), vector.answer)
      assert.deepEqual(await reader.classC(vector.q), vector.classC)
    })
  }
  reader.clear()
})

test('unknown query only loads the indexed router, not every object', async () => {
  const paths = []
  const reader = new AtlasReader((path, options) => { paths.push(path); return response(path, options) }, () => golden.clock)
  const answer = await reader.lookup('8.8.8.8')
  assert.equal(answer.network, null)
  assert.equal(paths.filter(path => path.endsWith('.via3')).length, 1)
  reader.clear()
})

test('input errors precede any query-specific data request', async () => {
  const reader = new AtlasReader(() => { throw new Error('unexpected fetch') }, () => golden.clock)
  await assert.rejects(reader.lookup('example.test'), { message: 'invalid_input' })
})

test('native fetch keeps its worker-global receiver', async () => {
  const reader = new AtlasReader(function (path, options) {
    assert.equal(this, globalThis)
    return response(path, options)
  }, () => golden.clock)
  await reader.lookup('203.0.113.1')
  reader.clear()
})

test('full-integrity hostile Go containers cannot manufacture public facts', async t => {
  const hostile = JSON.parse(readFileSync(new URL('../../fixtures/bin/semantic-hostile-via3.json', import.meta.url), 'utf8'))
  for (const vector of hostile) {
    await t.test(vector.name, async () => {
      const objects = new Map(vector.objects.map(object => [`/_atlas/objects/${object.sha256}.via3`, new Uint8Array(Buffer.from(object.base64, 'base64'))]))
      objects.set('/_atlas/current.json', new TextEncoder().encode(stable(vector.pointer)))
      objects.set(vector.pointer.manifest_path, new TextEncoder().encode(stable(vector.manifest)))
      const reader = new AtlasReader(async path => new Response(objects.get(path), { status: objects.has(path) ? 200 : 404 }), () => vector.clock)
      await assert.rejects(reader.lookup(vector.q), { message: vector.error })
      reader.clear()
    })
  }
})

test('length, version, overflow and checksum failures remain closed', async () => {
  const good = new Uint8Array(Buffer.from(golden.objects[0].base64, 'base64'))
  await assert.rejects(parseShard(good.subarray(0, 63)), { message: 'length' })
  await assert.rejects(parseShard(new Uint8Array(24 * 1024 * 1024)), { message: 'length' })
  const version = good.slice(); version[6] = 4
  await assert.rejects(parseShard(version), { message: 'version' })
  const reserved = good.slice(); reserved[45] = 1
  await assert.rejects(parseShard(reserved), { message: 'header' })
  const overflow = good.slice(); new DataView(overflow.buffer).setBigUint64(72, 0xffffffffffffffffn, true)
  await assert.rejects(parseShard(overflow), { message: 'bounds' })
  const checksum = good.slice(); checksum[checksum.length - 1] ^= 1
  await assert.rejects(parseShard(checksum), { message: 'integrity' })
})

test('unchanged pointer and cached objects cannot extend release expiry', async () => {
  let now = golden.clock
  const reader = new AtlasReader(response, () => now)
  await reader.lookup('203.0.113.1')
  now = golden.manifest.valid_until
  await assert.rejects(reader.lookup('203.0.113.1'), { message: 'expired' })
  await assert.rejects(reader.classC('8.8.8.8'), { message: 'expired' })
  await assert.rejects(reader.classC('2001:db8::1'), { message: 'expired' })
  await assert.rejects(reader.prefixes('AS3356'), { message: 'expired' })
  reader.clear()
})

test('cancelled queries never expose decoded answers', async () => {
  const controller = new AbortController(); controller.abort()
  const reader = new AtlasReader(response, () => golden.clock)
  await assert.rejects(reader.lookup('203.0.113.1', controller.signal), { name: 'AbortError' })
})

test('public profile rejects a declared decode bomb before decompression', async () => {
  const bytes = new Uint8Array(Buffer.from(golden.objects[0].base64, 'base64'))
  new DataView(bytes.buffer).setBigUint64(36, 32n * 1024n * 1024n + 1n, true)
  await assert.rejects(parseShard(bytes), { message: 'resource_limit' })
})

test('resident ledger counts shared router/cache buffers once', () => {
  const reader = new AtlasReader(response, () => golden.clock)
  const object = 32 * 1024 * 1024
  reader.beginQuery()
  reader.admit('router', object)
  reader.residents.get('router').router = true
  reader.residents.get('router').cache = true
  reader.endQuery()
  reader.beginQuery()
  reader.admit('first', object)
  reader.admit('second', object)
  assert.equal(reader.residentBytes, 96 * 1024 * 1024)
  assert.throws(() => reader.admit('overflow', 1), { message: 'resource_limit' })
  reader.endQuery()
  assert.equal(reader.residentBytes, object)
  assert.equal(reader.active.size, 0)
  reader.clear()
})

test('query pins release on success, failure and cancellation', async () => {
  const reader = new AtlasReader(response, () => golden.clock)
  const released = () => {
    assert.equal(reader.active.size, 0)
    assert.equal(reader.activeReserved.size, 0)
    for (const entry of reader.residents.values()) assert.equal(entry.query, false)
  }
  await reader.lookup('203.0.113.1'); released()
  await reader.classC('203.0.113.1'); released()
  await assert.rejects(reader.prefixes('AS13335', 99), { message: 'invalid_cursor' }); released()
  const controller = new AbortController(); controller.abort()
  await assert.rejects(reader.lookup('203.0.113.1', controller.signal), { name: 'AbortError' }); released()
  reader.clear()
})

test('self-consistent manifest identities cannot extend the maximum interval', async () => {
  const manifest = { ...golden.manifest, valid_until: golden.manifest.valid_from + 721 * 3600 }
  const { release_id: _id, ...descriptor } = manifest
  manifest.release_id = await hash(new TextEncoder().encode(stable(descriptor)))
  const pointer = { format_version: 3, release_id: manifest.release_id, manifest_path: `/_atlas/releases/${manifest.release_id}/manifest.json`, manifest_sha256: await hash(new TextEncoder().encode(stable(manifest))) }
  let objectRequests = 0
  const reader = new AtlasReader(async path => {
    if (path.endsWith('.via3')) objectRequests++
    const bytes = path === '/_atlas/current.json' ? new TextEncoder().encode(stable(pointer)) : path === pointer.manifest_path ? new TextEncoder().encode(stable(manifest)) : files.get(path)
    return new Response(bytes, { status: bytes ? 200 : 404 })
  }, () => golden.clock)
  await assert.rejects(reader.lookup('203.0.113.1'), { message: 'manifest' })
  assert.equal(objectRequests, 0)
  reader.clear()
})

test('hot lookups reuse a verified pointer lease and revalidate by sixty seconds', async () => {
  let elapsed = 0
  let pointers = 0
  const reader = new AtlasReader((path, options) => { if (path === '/_atlas/current.json') pointers++; return response(path, options) }, () => golden.clock, () => {}, () => elapsed)
  await reader.lookup('203.0.113.1')
  await reader.lookup('AS13335')
  elapsed = 59.999
  await reader.lookup('203.0.113.200')
  assert.equal(pointers, 1)
  elapsed = 60
  await reader.lookup('203.0.113.1')
  assert.equal(pointers, 2)
  reader.clear()
})

test('failed proactive verification never renews the hard pointer deadline', async () => {
  let elapsed = 0
  let offline = false
  const invalidations = []
  const reader = new AtlasReader((path, options) => { if (offline) return Promise.reject(new Error('offline')); return response(path, options) }, () => golden.clock, reason => invalidations.push(reason), () => elapsed)
  await reader.lookup('203.0.113.1')
  const epoch = reader.leaseEpoch
  offline = true; elapsed = 55
  await reader.revalidate(epoch)
  assert.equal(reader.pointerCheckedAt, 0)
  elapsed = 60
  reader.leaseDeadline(epoch)
  assert.equal(reader.manifest, null)
  assert.ok(invalidations.includes('pointer_lease_expired'))
  await assert.rejects(reader.lookup('203.0.113.1'), { message: 'offline' })
  reader.clear()
})

test('a changed pointer retracts pinned cached facts before replacement lookup', async () => {
  let elapsed = 0
  let changed = false
  const invalidations = []
  const pointer = { format_version: 3, release_id: '0'.repeat(64), manifest_path: `/_atlas/releases/${'0'.repeat(64)}/manifest.json`, manifest_sha256: 'f'.repeat(64) }
  const reader = new AtlasReader((path, options) => changed && path === '/_atlas/current.json' ? Promise.resolve(new Response(stable(pointer))) : response(path, options), () => golden.clock, reason => invalidations.push(reason), () => elapsed)
  await reader.lookup('203.0.113.1')
  elapsed = 55; changed = true
  await reader.revalidate(reader.leaseEpoch)
  assert.equal(reader.manifest, null)
  assert.ok(invalidations.includes('release_changed'))
  await assert.rejects(reader.lookup('203.0.113.1'), { message: 'missing_object' })
  reader.clear()
})

test('corrupt cached values cannot become allocation lengths or array-like buffers', async () => {
  const previous = Object.getOwnPropertyDescriptor(globalThis, 'indexedDB')
  Object.defineProperty(globalThis, 'indexedDB', { value: {}, configurable: true })
  try {
  const reader = new AtlasReader(response, () => golden.clock)
  const deleted = []
  let value
  const fakeDatabase = {
    transaction: () => ({ objectStore: name => ({
      get: () => { const request = {}; queueMicrotask(() => { request.result = value; request.onsuccess() }); return request },
      delete: key => deleted.push([name, key]),
    }) }),
  }
  reader.persistent.database = Promise.resolve(fakeDatabase)
  for (value of [1000000000, { length: 1000000000 }, new Uint8Array(128), new ArrayBuffer(256)]) {
    await assert.rejects(reader.persistent.get('0'.repeat(64), 128), { message: 'integrity' })
  }
  assert.equal(deleted.length, 8)
  value = new ArrayBuffer(128)
  const bytes = await reader.persistent.get('0'.repeat(64), 128)
  assert.equal(bytes.buffer, value)
  assert.equal(bytes.byteLength, 128)
  reader.clear()
  } finally {
    if (previous) Object.defineProperty(globalThis, 'indexedDB', previous)
    else delete globalThis.indexedDB
  }
})
