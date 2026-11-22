import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import test from 'node:test'
import { AtlasReader, parseShard, hash, answerJSONBytes, PathSegmentPool, prefixKeyValid, comparePrefixKeys } from '../../web/app/workers/atlas.ts'
import { hasMapLocation } from '../../web/app/lib/via3.ts'
import { rpkiSnapshotTiming, trackSnapshotTime } from '../../web/app/lib/rpkiSnapshot.ts'

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

test('RPKI snapshot timing keeps historical statuses distinct from unavailable at the expiry boundary', () => {
  for (const status of ['valid', 'invalid', 'not_found']) {
    const row = { origin: 13335, status, observedAt: 1_800_000_000, validUntil: 1_800_000_060 }
    assert.equal(rpkiSnapshotTiming(row, row.validUntil - .001).expired, false)
    assert.equal(rpkiSnapshotTiming(row, row.validUntil).expired, true)
    assert.equal(rpkiSnapshotTiming(row, row.validUntil + 86_400).expired, true)
    assert.equal(row.status, status, 'Passing a deadline does not change a recorded result')
    assert.match(rpkiSnapshotTiming(row, row.validUntil).observedAt, / UTC$/)
    assert.match(rpkiSnapshotTiming(row, row.validUntil).validUntil, / UTC$/)
  }
  assert.equal(rpkiSnapshotTiming({ origin: 13335, status: 'unavailable', observedAt: null, validUntil: null }, 1_800_000_000), null)
  assert.match(rpkiSnapshotTiming({ origin: 13335, status: 'valid', observedAt: Number.MAX_SAFE_INTEGER - 1, validUntil: Number.MAX_SAFE_INTEGER }, 0).validUntil, /seconds since Unix epoch$/)
})

test('snapshot labels update on the timer and immediately after tab resume, and stop after cleanup', t => {
  t.mock.timers.enable({ apis: ['Date', 'setInterval'], now: 1_800_000_000_000 })
  const target = new EventTarget(), states = []
  const row = { origin: 13335, status: 'valid', observedAt: 1_799_999_900, validUntil: 1_800_000_002 }
  const stop = trackSnapshotTime(now => states.push(rpkiSnapshotTiming(row, now).expired), target)
  assert.deepEqual(states, [false])
  t.mock.timers.tick(1_000)
  assert.deepEqual(states, [false, false])
  t.mock.timers.tick(1_000)
  assert.equal(states.at(-1), true)
  t.mock.timers.setTime(1_800_000_003_000)
  const count = states.length
  target.dispatchEvent(new Event('visibilitychange'))
  assert.equal(states.length, count + 1, 'Resume does not wait for another timer interval')
  assert.equal(states.at(-1), true)
  stop()
  t.mock.timers.tick(5_000)
  target.dispatchEvent(new Event('visibilitychange'))
  assert.equal(states.length, count + 1)
})

test('city and finer area coordinates can show a map while missing, coarse and anycast data remain unknown', () => {
  const answer = { geo: { latitude: 0, longitude: 0, precision: 'area' }, usage: null }
  assert.equal(hasMapLocation(answer), true, 'VIA3 precision 4 is a finer evidenced area')
  assert.equal(hasMapLocation({ ...answer, geo: { ...answer.geo, precision: 'city_centroid' } }), true)
  for (const precision of [null, 'unknown', 'country', 'region']) assert.equal(hasMapLocation({ ...answer, geo: { ...answer.geo, precision } }), false)
  assert.equal(hasMapLocation({ ...answer, geo: { ...answer.geo, latitude: null } }), false)
  assert.equal(hasMapLocation({ ...answer, geo: { ...answer.geo, longitude: null } }), false)
  assert.equal(hasMapLocation({ ...answer, usage: { anycast: true } }), false)
  assert.equal(hasMapLocation({ geo: null, usage: null }), false)
  assert.equal(hasMapLocation(null), false)
})

test('worker SHA-256 preserves standard digests, sliced inputs and maximum-sized sections', async () => {
  for (const [text, expected] of [
    ['', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
    ['abc', 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'],
    ['abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq', '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1'],
  ]) {
    const result = hash(new TextEncoder().encode(text))
    assert(result instanceof Promise)
    assert.equal(await result, expected)
  }
  for (const size of [1, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129, 255, 256, 257, 4095, 4096, 4097, 1024 * 1024, 32 * 1024 * 1024]) {
    const storage = new Uint8Array(size + 17).fill(0xa5)
    const input = storage.subarray(7, size + 7)
    for (let i = 0; i < input.length; i++) input[i] = (i * 37 + (i >>> 9)) & 255
    const expected = createHash('sha256').update(input).digest('hex')
    assert.equal(await hash(input), expected, `section length ${size}`)
    assert.equal(createHash('sha256').update(input).digest('hex'), expected, 'Hashing must leave its owned input unchanged')
    assert(storage.subarray(0, 7).every(value => value === 0xa5))
    assert(storage.subarray(size + 7).every(value => value === 0xa5))
  }
})

test('bounded answer byte counting matches JSON UTF-8 without materializing the complete serialization', () => {
  const encoder = new TextEncoder()
  const samples = [null, true, false, 0, -0, 1e-7, 1e21, -1.25, '\\"\n\r\t\b\f\u0000\u001f',
    'Atlas é 中 😀', '\ud800x\udfff', '\ud800\udfff', [], {}, { q: 'AS13335', nested: [null, 0, { label: 'é' }] }]
  let seed = 0xace1
  for (let sample = 0; sample < 128; sample++) {
    let text = ''
    for (let i = 0; i < sample; i++) { seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0; text += String.fromCharCode(seed >>> 16) }
    samples.push({ [text]: [text, sample] })
  }
  for (const value of samples) {
    const expected = encoder.encode(JSON.stringify(value)).length
    assert.equal(answerJSONBytes(value, expected), expected)
    assert.throws(() => answerJSONBytes(value, expected - 1), { message: 'resource_limit' })
  }
  const maximum = { text: 'x'.repeat(8 * 1024 * 1024 - 11) }
  assert.equal(answerJSONBytes(maximum), 8 * 1024 * 1024)
  maximum.text += 'x'
  assert.throws(() => answerJSONBytes(maximum), { message: 'resource_limit' })
})

test('path sharing preserves exact segment types, sequence order and serialized answer bytes', () => {
  const pool = new PathSegmentPool()
  const sequences = [
    [{ type: 'sequence', asns: [13335, 3356] }],
    [{ type: 'sequence', asns: [13335, 3356] }],
    [{ type: 'set', asns: [13335, 3356] }],
    [{ type: 'sequence', asns: [3356, 13335] }],
    [{ type: 'sequence', asns: [1, 23] }],
    [{ type: 'sequence', asns: [12, 3] }],
    [{ type: 'sequence', asns: [13335] }, { type: 'set', asns: [3356] }],
    [{ type: 'set', asns: [3356] }, { type: 'sequence', asns: [13335] }],
  ]
  const before = JSON.stringify(sequences)
  const shared = sequences.map(segments => pool.intern(segments))
  assert.equal(JSON.stringify(shared), before)
  assert.equal(shared[0], shared[1])
  for (let i = 2; i < shared.length; i++) assert.notEqual(shared[0], shared[i])
  assert.notEqual(shared[4], shared[5])
  assert.notEqual(shared[6], shared[7])
  const clone = structuredClone(shared)
  assert.equal(clone[0], clone[1], 'The consumer shares exact sequences without losing any paths')
  const first = pool.singleton(1, 4199999999)
  assert.deepEqual(first, [{ type: 'sequence', asns: [4199999999] }])
  assert.equal(pool.singleton(1, 4199999999), first)
  assert.notEqual(pool.singleton(2, 4199999999), first)
  assert.deepEqual(pool.singleton(4, 1), [{ type: 'confederation_set', asns: [1] }])
  for (let i = 0; i < 1024; i++) pool.singleton(1, i + 1)
  assert.deepEqual(first, [{ type: 'sequence', asns: [4199999999] }])
  for (let i = 0; i < 1024; i++) pool.intern([{ type: 'sequence', asns: [i + 1] }])
  assert.equal(JSON.stringify(shared), before, 'Eviction cannot change a previously materialized answer')
  assert(pool.size <= 256)
  assert(pool.keyBytes <= 128 * 1024)
})

test('offset prefix validation preserves the prior key rules at hostile boundaries', () => {
  const u16 = (row, p) => new DataView(row.buffer, row.byteOffset, row.byteLength).getUint16(p, true)
  const zero = bytes => bytes.every(value => value === 0)
  const priorValid = row => {
    const width = row[0] === 4 ? 32 : row[0] === 6 ? 128 : 0
    if (!width || row[1] > width || u16(row, 2) > 1 || (row.length >= 32 && !zero(row.subarray(24, 32)))) return false
    if (width === 32 && !zero(row.subarray(4, 16))) return false
    if (width === 128 && zero(row.subarray(4, 14)) && row[14] === 255 && row[15] === 255) return false
    if (u16(row, 2) === 1 && row[1] !== width) return false
    const offset = width === 32 ? 16 : 4
    for (let bit = row[1]; bit < width; bit++) if (row[offset + Math.floor(bit / 8)] & (1 << (7 - bit % 8))) return false
    return true
  }
  const priorCompare = (a, b) => {
    if (a[0] !== b[0]) return a[0] - b[0]
    for (let i = 4; i < 20; i++) if (a[i] !== b[i]) return a[i] - b[i]
    return a[1] !== b[1] ? a[1] - b[1] : u16(a, 2) - u16(b, 2)
  }
  const rows = []
  for (const family of [4, 6]) for (let bits = 0; bits <= (family === 4 ? 32 : 128); bits++) {
    const row = new Uint8Array(32), offset = family === 4 ? 16 : 4, width = family === 4 ? 32 : 128
    row[0] = family; row[1] = bits
    for (let i = offset; i < 20; i++) row[i] = (i * 37 + bits * 13) & 255
    for (let bit = bits; bit < width; bit++) row[offset + Math.floor(bit / 8)] &= ~(1 << (7 - bit % 8))
    rows.push(row)
    for (const [position, value] of [[0, 5], [1, width + 1], [2, 1], [2, 2], [3, 1], [24, 1], [31, 1]]) {
      const hostile = row.slice(); hostile[position] = value; rows.push(hostile)
    }
    if (bits < width) { const hostBits = row.slice(); hostBits[19] |= 1; rows.push(hostBits) }
    if (family === 4) { const leading = row.slice(); leading[4] = 1; rows.push(leading) }
  }
  const mapped = new Uint8Array(32); mapped[0] = 6; mapped[1] = 128; mapped[14] = mapped[15] = 255; rows.push(mapped)
  for (let i = 0; i < rows.length; i++) {
    const row = rows[i], next = rows[(i * 37 + 11) % rows.length]
    const storage = new Uint8Array(103); storage.set(row, 7); storage.set(next, 61)
    assert.equal(prefixKeyValid(storage, 7, 32), priorValid(row))
    assert.equal(prefixKeyValid(storage, 7, 24), priorValid(row.subarray(0, 24)))
    assert.equal(comparePrefixKeys(storage, 7, storage, 61), priorCompare(row, next))
    assert.equal(comparePrefixKeys(storage, 61, storage, 7), priorCompare(next, row))
  }
})

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

test('RPKI snapshot expiry preserves observed results while whole-release expiry remains enforced', async () => {
  let now = golden.clock
  const reader = new AtlasReader(response, () => now)
  try {
    const before = await reader.lookup('203.0.113.1')
    const known = before.bgp.rpki.filter(row => row.status !== 'unavailable')
    assert(known.some(row => row.validUntil <= now), 'The shared fixture includes an expired known result')
    assert(known.some(row => row.validUntil > now && row.validUntil < before.validUntil))
    now = Math.max(...known.map(row => row.validUntil))
    const after = await reader.lookup('203.0.113.1')
    assert.deepEqual(after, before, 'RPKI expiry changes presentation, not recorded answers or other facts')
    assert(after.bgp.rpki.every(row => rpkiSnapshotTiming(row, now).expired))
    const unknown = await reader.lookup('203.0.114.1')
    assert(unknown.bgp.rpki.every(row => row.status === 'unavailable' && row.observedAt === null && row.validUntil === null))
    now = before.validUntil
    await assert.rejects(reader.lookup('203.0.113.1'), { message: 'expired' })
  } finally { reader.clear() }
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

test('independent fact partitions preserve complete Go/worker lookup and Class C answers', async t => {
  const fixture = JSON.parse(readFileSync(new URL('../../fixtures/bin/grouped-via3.json', import.meta.url), 'utf8'))
  const objects = new Map(fixture.objects.map(object => [`/_atlas/objects/${object.info.sha256}.via3`, new Uint8Array(Buffer.from(object.base64, 'base64'))]))
  objects.set('/_atlas/current.json', new TextEncoder().encode(canonical(fixture.pointer)))
  objects.set(fixture.pointer.manifest_path, new TextEncoder().encode(stable(fixture.manifest)))
  const reader = new AtlasReader(path => {
    const data = objects.get(path)
    return Promise.resolve(new Response(data, { status: data ? 200 : 404, headers: { 'content-length': String(data?.length ?? 0) } }))
  }, () => fixture.clock)
  try {
    for (const vector of fixture.vectors) await t.test(vector.q, async () => {
      assert.deepEqual(await reader.lookup(vector.q), vector.answer)
      assert.deepEqual(await reader.lookup(vector.q), vector.answer, 'Cached and repeated grouped lookups agree')
      assert.deepEqual(await reader.classC(vector.q), vector.classC)
    })
  } finally { reader.clear() }
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
  for (const oldSchema of [3, 4]) {
    const version = good.slice(); version[6] = oldSchema
    await assert.rejects(parseShard(version), { message: 'version' })
  }
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

test('decoded storage is detached only after its final query, cache and router pin is released', async () => {
  const reader = new AtlasReader(response, () => golden.clock)
  const expected = await reader.lookup('203.0.113.1')
  const routerKey = [...reader.residents].find(([, entry]) => entry.router)[0]
  const key = [...reader.residents].find(([, entry]) => !entry.router)[0]
  const shard = reader.cache.get(key)
  const buffers = [...shard.sections.values()].map(section => section.buffer)
  reader.beginQuery()
  await reader.object(key)
  reader.evictCache(key)
  assert(buffers.every(buffer => buffer.byteLength > 0), 'The active query still owns the shard')
  reader.endQuery()
  assert(buffers.every(buffer => buffer.byteLength === 0), 'The last pin releases decoded backing stores immediately')
  assert.deepEqual(await reader.lookup('203.0.113.1'), expected, 'A later lookup reloads identical verified facts')
  const routerBuffers = [...reader.router.sections.values()].map(section => section.buffer)
  reader.evictCache(routerKey)
  assert(routerBuffers.every(buffer => buffer.byteLength > 0), 'The router pin survives cache eviction')
  const retained = [...reader.cache.values()].flatMap(shard => [...shard.sections.values()].map(section => section.buffer))
  assert(retained.every(buffer => buffer.byteLength > 0), 'End-of-query preserves cached objects')
  reader.clear()
  assert([...routerBuffers, ...retained].every(buffer => buffer.byteLength === 0))
  assert.deepEqual(await reader.lookup('203.0.113.1'), expected, 'Clearing cannot corrupt a subsequent release lookup')
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

test('owned compressed objects remain valid until asynchronous cache writes complete', async () => {
  const reader = new AtlasReader(response, () => golden.clock)
  const stored = []
  reader.persistent = {
    get: async () => null,
    put: async (key, bytes) => {
      const expected = files.get(`/_atlas/objects/${key}.via3`)
      assert.deepEqual(bytes, expected)
      await new Promise(resolve => setImmediate(resolve))
      assert.deepEqual(bytes, expected, 'Do not detach while the cache transaction borrows its input')
      stored.push(bytes)
    },
  }
  try {
    const answer = await reader.lookup('203.0.113.1')
    assert(stored.length > 0)
    assert(stored.every(bytes => bytes.buffer.byteLength === 0), 'Compressed inputs are released after the write finishes')
    assert.deepEqual(await reader.lookup('203.0.113.1'), answer, 'Decoded cache entries survive compressed-input cleanup')
  } finally { reader.clear() }
})

test('owned cached compressed bytes are released after success, corruption and cancellation', async () => {
  for (const outcome of ['success', 'corrupt', 'cancelled']) {
    const controller = new AbortController()
    const reader = new AtlasReader(response, () => golden.clock)
    const inputs = []
    const evicted = []
    reader.persistent = {
      get: async key => {
        const bytes = files.get(`/_atlas/objects/${key}.via3`).slice()
        if (outcome === 'corrupt') bytes[bytes.length - 1] ^= 1
        if (outcome === 'cancelled') controller.abort()
        inputs.push(bytes)
        return bytes
      },
      evict: async key => { assert(inputs.at(-1).byteLength > 0); evicted.push(key) },
      put: async () => assert.fail('Cached objects should not be written again'),
    }
    try {
      if (outcome === 'success') await reader.lookup('203.0.113.1', controller.signal)
      else await assert.rejects(reader.lookup('203.0.113.1', controller.signal), outcome === 'corrupt' ? { message: 'integrity' } : { name: 'AbortError' })
      assert(inputs.length > 0)
      assert(inputs.every(bytes => bytes.buffer.byteLength === 0))
      assert.equal(evicted.length, outcome === 'corrupt' ? 1 : 0)
    } finally { reader.clear() }
  }
  for (const object of golden.objects) assert.equal(await hash(files.get(`/_atlas/objects/${object.info.sha256}.via3`)), object.info.sha256)
})

test('worker fetches only destination kinds used by each operation and verifies them when read', async () => {
  const byPath = new Map(golden.objects.map(({ info }) => [`/_atlas/objects/${info.sha256}.via3`, info.kind]))
  const checkReadKinds = async (allowed, run) => {
    const reader = new AtlasReader((path, options) => {
      if (byPath.has(path)) assert.ok(allowed.includes(byPath.get(path)), `Unexpected object kind ${byPath.get(path)}`)
      return response(path, options)
    }, () => golden.clock)
    try { await run(reader) } finally { reader.clear() }
  }
  await checkReadKinds([1, 8], reader => reader.prefixes('AS13335', 0))
  await checkReadKinds([1, 7, 4], reader => reader.classC('203.0.113.1'))
  const reader = new AtlasReader(async (path, options) => {
    if (byPath.get(path) !== 7) return response(path, options)
    const bytes = files.get(path).slice()
    bytes[bytes.length - 1] ^= 1
    return new Response(bytes, { status: 200 })
  }, () => golden.clock)
  try {
    await assert.rejects(reader.lookup(golden.vectors[0].q), { message: 'integrity' })
    await assert.rejects(reader.classC(golden.vectors[0].q), { message: 'integrity' })
  } finally { reader.clear() }
})
