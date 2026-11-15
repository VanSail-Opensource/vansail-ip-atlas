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
type Word64 = { low: number; high: number }
const P1_LOW = 0x85ebca87, P1_HIGH = 0x9e3779b1
const P2_LOW = 0x27d4eb4f, P2_HIGH = 0xc2b2ae3d
const P3_LOW = 0x9e3779f9, P3_HIGH = 0x165667b1
const P4_LOW = 0xc2b2ae63, P4_HIGH = 0x85ebca77
const P5_LOW = 0x165667c5, P5_HIGH = 0x27d4eb2f

function add64(value: Word64, low: number, high: number): void {
  const sum = value.low + low
  value.low = sum >>> 0
  value.high = (value.high + high + (sum >= 0x100000000 ? 1 : 0)) >>> 0
}
function multiply64(value: Word64, low: number, high: number): void {
  const a = value.low, b = value.high
  // Split the low-word product into 16-bit limbs. Every intermediate remains
  // an exact integer below 2^53; imul supplies the modulo-2^32 cross products.
  const a0 = a & 0xffff, a1 = a >>> 16, b0 = low & 0xffff, b1 = low >>> 16
  const carry = Math.floor((a0 * b0) / 0x10000) + a1 * b0 + a0 * b1
  value.low = Math.imul(a, low) >>> 0
  value.high = (Math.imul(b, low) + Math.imul(a, high) + a1 * b1 + Math.floor(carry / 0x10000)) >>> 0
}
function rotate64(value: Word64, bits: number): void {
  // XXH64 uses only rotations between 1 and 31 bits.
  const low = value.low, high = value.high
  value.low = ((low << bits) | (high >>> (32 - bits))) >>> 0
  value.high = ((high << bits) | (low >>> (32 - bits))) >>> 0
}
function round64(value: Word64, low: number, high: number, scratch: Word64): void {
  scratch.low = low; scratch.high = high
  multiply64(scratch, P2_LOW, P2_HIGH)
  add64(value, scratch.low, scratch.high)
  rotate64(value, 31)
  multiply64(value, P1_LOW, P1_HIGH)
}

export function zstdChecksum(input: Uint8Array): number {
  const view = new DataView(input.buffer, input.byteOffset, input.byteLength)
  // Reuse a fixed number of word pairs. BigInt arithmetic here used to create
  // temporary heap values for every eight decoded bytes of a large section.
  const scratch: Word64 = { low: 0, high: 0 }, mixed: Word64 = { low: 0, high: 0 }
  const hash: Word64 = { low: P5_LOW, high: P5_HIGH }
  let offset = 0
  if (input.length >= 32) {
    const v1: Word64 = { low: 0xadc0b5d6, high: 0x60ea27ee } // P1 + P2
    const v2: Word64 = { low: P2_LOW, high: P2_HIGH }
    const v3: Word64 = { low: 0, high: 0 }
    const v4: Word64 = { low: 0x7a143579, high: 0x61c8864e } // -P1
    while (offset <= input.length - 32) {
      round64(v1, view.getUint32(offset, true), view.getUint32(offset + 4, true), scratch); offset += 8
      round64(v2, view.getUint32(offset, true), view.getUint32(offset + 4, true), scratch); offset += 8
      round64(v3, view.getUint32(offset, true), view.getUint32(offset + 4, true), scratch); offset += 8
      round64(v4, view.getUint32(offset, true), view.getUint32(offset + 4, true), scratch); offset += 8
    }
    hash.low = 0; hash.high = 0
    const lanes = [v1, v2, v3, v4], rotations = [1, 7, 12, 18]
    for (let i = 0; i < lanes.length; i++) {
      mixed.low = lanes[i]!.low; mixed.high = lanes[i]!.high
      rotate64(mixed, rotations[i]!)
      add64(hash, mixed.low, mixed.high)
    }
    for (const lane of lanes) {
      mixed.low = 0; mixed.high = 0
      round64(mixed, lane.low, lane.high, scratch)
      hash.low ^= mixed.low; hash.high ^= mixed.high
      multiply64(hash, P1_LOW, P1_HIGH)
      add64(hash, P4_LOW, P4_HIGH)
    }
  }
  add64(hash, input.length >>> 0, Math.floor(input.length / 0x100000000))
  while (offset <= input.length - 8) {
    mixed.low = 0; mixed.high = 0
    round64(mixed, view.getUint32(offset, true), view.getUint32(offset + 4, true), scratch)
    hash.low ^= mixed.low; hash.high ^= mixed.high
    rotate64(hash, 27)
    multiply64(hash, P1_LOW, P1_HIGH)
    add64(hash, P4_LOW, P4_HIGH)
    offset += 8
  }
  if (offset <= input.length - 4) {
    mixed.low = view.getUint32(offset, true); mixed.high = 0
    multiply64(mixed, P1_LOW, P1_HIGH)
    hash.low ^= mixed.low; hash.high ^= mixed.high
    rotate64(hash, 23)
    multiply64(hash, P2_LOW, P2_HIGH)
    add64(hash, P3_LOW, P3_HIGH)
    offset += 4
  }
  while (offset < input.length) {
    mixed.low = input[offset++]!; mixed.high = 0
    multiply64(mixed, P5_LOW, P5_HIGH)
    hash.low ^= mixed.low; hash.high ^= mixed.high
    rotate64(hash, 11)
    multiply64(hash, P1_LOW, P1_HIGH)
  }
  hash.low ^= hash.high >>> 1 // xor with hash >> 33
  multiply64(hash, P2_LOW, P2_HIGH)
  hash.low ^= (hash.low >>> 29) | (hash.high << 3)
  hash.high ^= hash.high >>> 29
  multiply64(hash, P3_LOW, P3_HIGH)
  return (hash.low ^ hash.high) >>> 0 // xor with hash >> 32
}

/** Pinned, bundled Zstandard only. No native/remote/alternate-codec fallback. */
export async function decodeZstd(input: Uint8Array, expectedLength: number): Promise<Uint8Array> {
  const { checksumOffset } = inspectZstdFrame(input, expectedLength)
  // All header-driven bounds above precede both this allocation and the decoder.
  const output = new Uint8Array(expectedLength)
  let written = 0
  let previous: ArrayBuffer | null = null
  try {
    const decoder = new Decompress((chunk) => {
      // fzstd@0.1.1 allocates each streamed block separately from input and its
      // history window, but copies it into that window AFTER this callback.
      // Release only the preceding block, whose history copy is complete.
      if (previous && previous !== chunk.buffer && previous.byteLength) previous.transfer(0)
      previous = chunk.buffer as ArrayBuffer
      if (chunk.length > expectedLength - written) fail('limit', 'Decoder emitted more than declared output')
      output.set(chunk, written)
      written += chunk.length
    })
    decoder.push(input, true)
    if (written !== expectedLength) fail('integrity', 'Decoded section length mismatch')
    const checksum = new DataView(input.buffer, input.byteOffset + checksumOffset, 4).getUint32(0, true)
    if (zstdChecksum(output) !== checksum) fail('integrity', 'Frame content checksum mismatch')
    return output
  } catch (error) {
    output.fill(0)
    output.buffer.transfer(0)
    if (error instanceof ZstdError) throw error
    return fail('input', 'Malformed compressed section')
  } finally {
    // push has returned or unwound; its last block is no longer borrowed.
    const remaining = previous as ArrayBuffer | null
    if (remaining && remaining.byteLength) remaining.transfer(0)
  }
}
