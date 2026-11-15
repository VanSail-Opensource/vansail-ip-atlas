import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { createRequire } from 'node:module'
import { test } from 'node:test'
import { Decompress, decompress } from 'fzstd'
import { decodeZstd, inspectZstdFrame, zstdChecksum, ZstdError } from '../app/lib/zstd.ts'

const vectors = JSON.parse(readFileSync(new URL('../../tools/hosted/fixtures/zstd.json', import.meta.url), 'utf8'))
const bytes = (vector: { encoded_base64: string }) => new Uint8Array(Buffer.from(vector.encoded_base64, 'base64'))

test('pinned Go frames match byte length and SHA256 in the bundled decoder', async () => {
  for (const vector of vectors) {
    const output = await decodeZstd(bytes(vector), vector.decoded_bytes)
    assert.equal(output.length, vector.decoded_bytes)
    assert.equal(createHash('sha256').update(output).digest('hex'), vector.decoded_sha256)
  }
})

test('XXH64 empty checksum matches the reference Zstandard value', () => {
  assert.equal(zstdChecksum(new Uint8Array()), 0x51d8e999)
})

test('oversized windows and 64-bit size bombs fail in pre-allocation framing', () => {
  const windowBomb = new Uint8Array([0x28, 0xb5, 0x2f, 0xfd, 0x84, 0xf8, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0])
  const sizeBomb = new Uint8Array([0x28, 0xb5, 0x2f, 0xfd, 0xe4, 0, 0, 0, 0, 0, 0, 0, 0x80, 1, 0, 0, 0, 0, 0, 0])
  for (const input of [windowBomb, sizeBomb]) {
    assert.throws(() => inspectZstdFrame(input, 1), (error) => error instanceof ZstdError && error.code === 'limit')
  }
})

test('unbounded output and strict 24 MiB input are rejected', async () => {
  await assert.rejects(decodeZstd(bytes(vectors[1]), 64 * 1024 * 1024 + 1), ZstdError)
  await assert.rejects(decodeZstd(new Uint8Array(24 * 1024 * 1024), 1), ZstdError)
  for (const expected of [-1, NaN, Infinity, 1.5]) await assert.rejects(decodeZstd(bytes(vectors[1]), expected), ZstdError)
})

test('content size mismatch, skippable and concatenated frames fail', async () => {
  await assert.rejects(decodeZstd(bytes(vectors[1]), vectors[1].decoded_bytes - 1), ZstdError)
  await assert.rejects(decodeZstd(new Uint8Array([0x50, 0x2a, 0x4d, 0x18, 0, 0, 0, 0, 0]), 0), ZstdError)
  const first = bytes(vectors[1])
  const concatenated = new Uint8Array(first.length * 2)
  concatenated.set(first)
  concatenated.set(first, first.length)
  await assert.rejects(decodeZstd(concatenated, vectors[1].decoded_bytes), ZstdError)
})

test('a compressed block cannot emit beyond a forged small content size', async () => {
  const original = bytes(vectors[2])
  const forged = new Uint8Array(original.length + 1)
  forged.set([0x28, 0xb5, 0x2f, 0xfd, 0x84, 0x68, 16, 0, 0, 0])
  forged.set(original.subarray(9), 10)
  const unchanged = forged.slice()
  inspectZstdFrame(forged, 16)
  await assert.rejects(decodeZstd(forged, 16), (error) => error instanceof ZstdError && error.code === 'limit')
  assert.deepEqual(forged, unchanged, 'Failure cleanup must not detach or modify the caller input')
})

test('checksums, truncation, dictionary IDs and reserved flags are checked', async () => {
  const original = bytes(vectors[1])
  const badChecksum = original.slice()
  badChecksum[badChecksum.length - 1] ^= 1
  await assert.rejects(decodeZstd(badChecksum, vectors[1].decoded_bytes), (error) => error instanceof ZstdError && error.code === 'integrity')
  for (let length = 0; length < original.length; length++)
    await assert.rejects(decodeZstd(original.slice(0, length), vectors[1].decoded_bytes), ZstdError)
  for (const flag of [1, 2, 3, 8, 16]) {
    const invalid = original.slice()
    invalid[4] |= flag
    await assert.rejects(decodeZstd(invalid, vectors[1].decoded_bytes), ZstdError)
  }
  const noChecksum = original.slice()
  noChecksum[4] &= ~4
  await assert.rejects(decodeZstd(noChecksum, vectors[1].decoded_bytes), ZstdError)
})

test('malformed block type and oversized block fail before decoder allocation', () => {
  const input = bytes(vectors[1])
  // This vector's frame header has one content-size byte; first block starts at6.
  const reserved = input.slice()
  reserved[6] = reserved[6]! | 6
  assert.throws(() => inspectZstdFrame(reserved, vectors[1].decoded_bytes), ZstdError)
  const oversized = input.slice()
  oversized[6] = 0xf9; oversized[7] = 0xff; oversized[8] = 0xff
  assert.throws(() => inspectZstdFrame(oversized, vectors[1].decoded_bytes), ZstdError)
})

// Independent BigInt specification retained only in tests. The production
// implementation must not allocate BigInts for every decoded eight-byte lane.
const MASK = (1n << 64n) - 1n
const P1 = 11400714785074694791n
const P2 = 14029467366897019727n
const P3 = 1609587929392839161n
const P4 = 9650029242287828579n
const P5 = 2870177450012600261n
const rotl = (value: bigint, bits: bigint) => ((value << bits) | (value >> (64n - bits))) & MASK
const round = (acc: bigint, lane: bigint) => rotl((acc + lane * P2) & MASK, 31n) * P1 & MASK

function referenceChecksum(input: Uint8Array): number {
  const view = new DataView(input.buffer, input.byteOffset, input.byteLength)
  let offset = 0
  let hash: bigint
  if (input.length >= 32) {
    let v1 = (P1 + P2) & MASK, v2 = P2, v3 = 0n, v4 = (-P1) & MASK
    while (offset <= input.length - 32) {
      v1 = round(v1, view.getBigUint64(offset, true)); offset += 8
      v2 = round(v2, view.getBigUint64(offset, true)); offset += 8
      v3 = round(v3, view.getBigUint64(offset, true)); offset += 8
      v4 = round(v4, view.getBigUint64(offset, true)); offset += 8
    }
    hash = (rotl(v1, 1n) + rotl(v2, 7n) + rotl(v3, 12n) + rotl(v4, 18n)) & MASK
    for (const lane of [v1, v2, v3, v4]) hash = ((hash ^ round(0n, lane)) * P1 + P4) & MASK
  } else hash = P5
  hash = (hash + BigInt(input.length)) & MASK
  while (offset <= input.length - 8) {
    hash = (rotl(hash ^ round(0n, view.getBigUint64(offset, true)), 27n) * P1 + P4) & MASK
    offset += 8
  }
  if (offset <= input.length - 4) {
    hash = (rotl(hash ^ (BigInt(view.getUint32(offset, true)) * P1 & MASK), 23n) * P2 + P3) & MASK
    offset += 4
  }
  while (offset < input.length) {
    hash = rotl(hash ^ (BigInt(input[offset++]!) * P5 & MASK), 11n) * P1 & MASK
  }
  hash ^= hash >> 33n
  hash = hash * P2 & MASK
  hash ^= hash >> 29n
  hash = hash * P3 & MASK
  hash ^= hash >> 32n
  return Number(hash & 0xffffffffn)
}


test('XXH64 limb arithmetic matches the BigInt specification at block and carry boundaries', () => {
  const lengths = [...Array.from({ length: 129 }, (_, i) => i), 255, 256, 257, 511, 512, 513, 4095, 4096, 4097, 65535, 65536, 65537]
  for (const fill of [0, 255, -1]) {
    const backing = new Uint8Array(65544 + 17)
    let random = 0x9e3779b9
    for (let i = 0; i < backing.length; i++) {
      random ^= random << 13; random ^= random >>> 17; random ^= random << 5
      backing[i] = fill < 0 ? random >>> 24 : fill
    }
    for (const length of lengths) {
      const input = backing.subarray(17, 17 + length)
      assert.equal(zstdChecksum(input), referenceChecksum(input), `fill=${fill}, length=${length}, nonzero byteOffset`)
    }
  }
})

test('streamed blocks retain history at the 8 MiB window limit without consuming caller input', async () => {
  const vector = vectors.find((item: { name: string }) => item.name === 'maximum-window-multiblock')
  const encoded = bytes(vector)
  const unchanged = encoded.slice()
  assert.equal(inspectZstdFrame(encoded, vector.decoded_bytes).window, 8 * 1024 * 1024)
  for (let repeat = 0; repeat < 2; repeat++) {
    const decoded = await decodeZstd(encoded, vector.decoded_bytes)
    assert.equal(decoded.length, 8 * 1024 * 1024)
    assert.equal(createHash('sha256').update(decoded).digest('hex'), vector.decoded_sha256)
    assert.deepEqual(encoded, unchanged)
  }
  encoded[encoded.length - 1] ^= 1
  const invalid = encoded.slice()
  await assert.rejects(decodeZstd(encoded, vector.decoded_bytes), (error) => error instanceof ZstdError && error.code === 'integrity')
  assert.deepEqual(encoded, invalid, 'Checksum failure cleanup leaves caller input intact')
})

test('patched decoder entry points preserve retained blocks across split and concatenated frames', () => {
  const commonjs = createRequire(import.meta.url)('fzstd') as { Decompress: typeof Decompress; decompress: typeof decompress }
  const input = new Uint8Array(Buffer.concat(vectors.map(bytes)))
  const unchanged = input.slice()
  const expected = createHash('sha256')
  let expectedLength = 0
  for (const vector of vectors) {
    const decoded = decompress(bytes(vector))
    assert.equal(createHash('sha256').update(decoded).digest('hex'), vector.decoded_sha256)
    expected.update(decoded); expectedLength += decoded.length
  }
  const expectedHash = expected.digest('hex')
  for (const decoder of [{ Decompress, decompress }, commonjs]) {
    assert.equal(createHash('sha256').update(decoder.decompress(input)).digest('hex'), expectedHash)
    for (const step of [1, 2, 3, 7, 64, 65536]) {
      const chunks: Uint8Array[] = []
      const stream = new decoder.Decompress(chunk => { chunks.push(chunk) })
      for (let offset = 0; offset < input.length; offset += step)
        stream.push(input.subarray(offset, offset + step), offset + step >= input.length)
      const retained = Buffer.concat(chunks)
      assert.equal(retained.length, expectedLength)
      assert.equal(createHash('sha256').update(retained).digest('hex'), expectedHash)
      assert.deepEqual(input, unchanged, 'Only decoder-owned backing stores may be detached')
    }
  }
})
