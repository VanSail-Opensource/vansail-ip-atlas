import { Decompress } from 'fzstd'

const MAX_COMPRESSED = 24 * 1024 * 1024
const MAX_OUTPUT = 64 * 1024 * 1024
const MAX_WINDOW = 8 * 1024 * 1024

export class ZstdError extends Error {
  readonly code: 'input' | 'limit' | 'integrity'
  constructor(code: 'input' | 'limit' | 'integrity', message: string) {
    super(message)
    this.name = 'ZstdError'
    this.code = code
  }
}

function fail(code: 'input' | 'limit' | 'integrity', message: string): never {
  throw new ZstdError(code, message)
}

/** Inspect all framing before the decoder can allocate from an untrusted header. */
export function inspectZstdFrame(input: Uint8Array, expectedLength: number): { checksumOffset: number; window: number } {
  if (!Number.isSafeInteger(expectedLength) || expectedLength < 0 || expectedLength > MAX_OUTPUT)
    fail('limit', 'Decoded section exceeds its hard limit')
  if (input.byteLength < 9 || input.byteLength >= MAX_COMPRESSED)
    fail('limit', 'Compressed section outside bounds')
  if (input[0] !== 0x28 || input[1] !== 0xb5 || input[2] !== 0x2f || input[3] !== 0xfd)
    fail('input', 'A single standard Zstandard frame is required')
  const descriptor = input[4]!
  const single = (descriptor & 0x20) !== 0
  if ((descriptor & 0x18) !== 0 || (descriptor & 3) !== 0)
    fail('input', 'Reserved flags or external dictionaries are forbidden')
  if ((descriptor & 4) === 0) fail('input', 'Frame checksum is required')
  let offset = 5
  let window = 0
  if (!single) {
    const value = input[offset++]!
    const base = 2 ** (10 + (value >>> 3))
    window = base + base / 8 * (value & 7)
    if (window > MAX_WINDOW) fail('limit', 'Decoder window exceeds 8 MiB')
  }
  const flag = descriptor >>> 6
  const sizeBytes = flag === 0 ? (single ? 1 : 0) : 2 ** flag
  if (sizeBytes === 0) fail('input', 'Frame content size is required')
  if (offset + sizeBytes > input.length) fail('input', 'Truncated frame header')
  let size = 0n
  for (let index = 0; index < sizeBytes; index++) size |= BigInt(input[offset + index]!) << BigInt(index * 8)
  offset += sizeBytes
  if (flag === 1) size += 256n
  if (size > BigInt(MAX_OUTPUT)) fail('limit', 'Frame output exceeds 64 MiB')
  if (size !== BigInt(expectedLength)) fail('integrity', 'Frame size disagrees with section descriptor')
  if (single) window = Number(size)
  if (window > MAX_WINDOW) fail('limit', 'Decoder window exceeds 8 MiB')
  let last = false
  while (!last) {
    if (offset + 3 > input.length) fail('input', 'Truncated block header')
    const block = input[offset]! | input[offset + 1]! << 8 | input[offset + 2]! << 16
    offset += 3
    last = (block & 1) !== 0
    const kind = (block >>> 1) & 3
    const size = block >>> 3
    if (kind === 3) fail('input', 'Reserved block type')
    if (size > Math.min(128 * 1024, window)) fail('limit', 'Block exceeds decoder window or 128 KiB')
    const encodedSize = kind === 1 ? 1 : size
    if (offset + encodedSize > input.length) fail('input', 'Truncated block payload')
    offset += encodedSize
  }
  if (offset + 4 !== input.length) fail('input', 'Truncated checksum, concatenated frame or trailing bytes')
  return { checksumOffset: offset, window }
}

// XXH64's low 32 bits are Zstandard's required frame content checksum. fzstd
// deliberately skips this checksum; verify it independently before exposing data.
const MASK = (1n << 64n) - 1n
const P1 = 11400714785074694791n
const P2 = 14029467366897019727n
const P3 = 1609587929392839161n
const P4 = 9650029242287828579n
const P5 = 2870177450012600261n
const rotl = (value: bigint, bits: bigint) => ((value << bits) | (value >> (64n - bits))) & MASK
const round = (acc: bigint, lane: bigint) => rotl((acc + lane * P2) & MASK, 31n) * P1 & MASK

export function zstdChecksum(input: Uint8Array): number {
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

/** Pinned, bundled Zstandard only. No native/remote/alternate-codec fallback. */
export async function decodeZstd(input: Uint8Array, expectedLength: number): Promise<Uint8Array> {
  const { checksumOffset } = inspectZstdFrame(input, expectedLength)
  // All header-driven bounds above precede both this allocation and the decoder.
  const output = new Uint8Array(expectedLength)
  let written = 0
  try {
    const decoder = new Decompress((chunk) => {
      if (chunk.length > expectedLength - written) fail('limit', 'Decoder emitted more than declared output')
      output.set(chunk, written)
      written += chunk.length
    })
    decoder.push(input, true)
  } catch (error) {
    output.fill(0)
    if (error instanceof ZstdError) throw error
    fail('input', 'Malformed compressed section')
  }
  if (written !== expectedLength) {
    output.fill(0)
    fail('integrity', 'Decoded section length mismatch')
  }
  const checksum = new DataView(input.buffer, input.byteOffset + checksumOffset, 4).getUint32(0, true)
  if (zstdChecksum(output) !== checksum) {
    output.fill(0)
    fail('integrity', 'Frame content checksum mismatch')
  }
  return output
}
