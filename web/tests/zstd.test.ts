import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { test } from 'node:test'
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
  inspectZstdFrame(forged, 16)
  await assert.rejects(decodeZstd(forged, 16), (error) => error instanceof ZstdError && error.code === 'limit')
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
