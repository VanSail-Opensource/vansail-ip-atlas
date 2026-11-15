const fail = () => { throw new Error('dataset_credits_unavailable') }
const MAX = 256 * 1024
function crc32(data: Uint8Array): number {
  let crc = 0xffffffff
  for (const value of data) {
    crc ^= value
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0)
  }
  return (crc ^ 0xffffffff) >>> 0
}
export async function verifyDatasetLogo(data: Uint8Array, digest: string, signal?: AbortSignal): Promise<string> {
  if (signal?.aborted || data.length > MAX || data.length < 45 || !/^[0-9a-f]{64}$/.test(digest)) return fail()
  const hash = [...new Uint8Array(await crypto.subtle.digest('SHA-256', data as BufferSource))].map(v => v.toString(16).padStart(2, '0')).join('')
  if (hash !== digest || ![137, 80, 78, 71, 13, 10, 26, 10].every((v, i) => data[i] === v)) return fail()
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength)
  let pos = 8, stage = 0, width = 0, height = 0, channels = 0, compressedSize = 0
  const pieces: Uint8Array[] = []
  while (pos + 12 <= data.length) {
    const size = view.getUint32(pos), kind = String.fromCharCode(...data.subarray(pos + 4, pos + 8))
    if (size > MAX || size > data.length - pos - 12 || crc32(data.subarray(pos + 4, pos + 8 + size)) !== view.getUint32(pos + 8 + size)) return fail()
    if (kind === 'IHDR') {
      if (stage !== 0 || size !== 13) return fail()
      width = view.getUint32(pos + 8); height = view.getUint32(pos + 12)
      channels = ({ 0: 1, 2: 3, 4: 2, 6: 4 } as Record<number, number>)[data[pos + 17]!] ?? 0
      if (!width || !height || width > 512 || height > 512 || data[pos + 16] !== 8 || !channels || data[pos + 18] || data[pos + 19] || data[pos + 20]) return fail()
      stage = 1
    } else if (kind === 'IDAT') {
      if (stage !== 1 && stage !== 2) return fail()
      pieces.push(data.subarray(pos + 8, pos + 8 + size)); compressedSize += size; stage = 2
    } else if (kind === 'IEND') {
      if (stage !== 2 || size || pos + 12 !== data.length) return fail()
      stage = 3
    } else return fail()
    pos += size + 12
  }
  if (pos !== data.length || stage !== 3 || !compressedSize) return fail()
  const compressed = new Uint8Array(compressedSize)
  let offset = 0
  for (const piece of pieces) { compressed.set(piece, offset); offset += piece.length }
  const expected = height * (1 + width * channels), row = 1 + width * channels
  const stream = new Blob([compressed]).stream().pipeThrough(new DecompressionStream('deflate')).getReader()
  let decoded = 0
  try {
    for (;;) {
      const { done, value } = await stream.read()
      if (done) break
      if (signal?.aborted || decoded + value.length > expected) return fail()
      for (let i = 0; i < value.length; i++) if ((decoded + i) % row === 0 && value[i]! > 4) return fail()
      decoded += value.length
    }
  } catch { return fail() }
  finally { await stream.cancel().catch(() => {}) }
  if (decoded !== expected || signal?.aborted) return fail()
  // Render the exact verified bytes. Re-fetching an img path would bypass the
  // verification decision if a cache or deployment changed between requests.
  let binary = ''
  for (let i = 0; i < data.length; i += 8192) binary += String.fromCharCode(...data.subarray(i, i + 8192))
  return 'data:image/png;base64,' + btoa(binary)
}
