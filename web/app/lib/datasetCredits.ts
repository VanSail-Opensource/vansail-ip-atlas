export type DatasetCredit = { name: string; text: string; url: string; license_url?: string }
export type CreditDocument = { format_version: 1; release_id: string; mode: 'synthetic' | 'production'; entries: DatasetCredit[] }
type CreditRef = { release_id: string; credits_path: string; credits_sha256: string }
type CreditIndex = { format_version: 1; current_release_id: string; releases: CreditRef[] }
const HASH = /^[0-9a-f]{64}$/
const LIMIT = 1024 * 1024
const SECRET = /(?:vless|vmess|trojan|ssr?|hy2?|hysteria2?|tuic|anytls):\/\/|-----BEGIN[^\r\n]*PRIVATE KEY-----|gh[pousr]_|github_pat_/i
const encoder = new TextEncoder()
const failure = () => { throw new Error('dataset_credits_unavailable') }
function object(value: unknown, keys: string[], optional: string[] = []): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return failure()
  const result = value as Record<string, unknown>
  if (keys.some(key => !(key in result)) || Object.keys(result).some(key => !keys.includes(key) && !optional.includes(key))) return failure()
  return result
}
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical((value as Record<string, unknown>)[key])}`).join(',')}}`
  return JSON.stringify(value)
}
function parse(bytes: Uint8Array, maximum: number): unknown {
  if (bytes.byteLength > maximum) return failure()
  const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes)
  const value: unknown = JSON.parse(text)
  if (canonical(value) !== text) return failure() // Also rejects duplicate keys.
  return value
}
function label(value: unknown, maximum: number): string {
  if (typeof value !== 'string' || !value || !value.isWellFormed() || value !== value.trim() || [...value].length > maximum || value.normalize('NFC') !== value || /[\p{Cc}\p{Cf}]/u.test(value) || SECRET.test(value)) return failure()
  return value
}
function publicHost(host: string): boolean {
  if (host.startsWith('[')) {
    const halves = host.slice(1, -1).split('::')
    const left = halves[0] ? halves[0].split(':') : [], right = halves[1] ? halves[1].split(':') : []
    const words = (halves.length === 2 ? [...left, ...Array(8 - left.length - right.length).fill('0'), ...right] : left).map(s => parseInt(s, 16))
    if (words.length === 8 && words.slice(0, 5).every(word => word === 0) && words[5] === 0xffff) return publicHost(`${words[6]! >> 8}.${words[6]! & 255}.${words[7]! >> 8}.${words[7]! & 255}`)
    const a = words[0]!, b = words[1]!
    return words.length === 8 && words.every(Number.isFinite) && a >= 0x2000 && a <= 0x3fff && !(a === 0x2001 && (b < 0x200 || b === 0xdb8)) && a !== 0x2002 && !(a === 0x3fff && b < 0x1000)
  }
  if (/^[0-9.]+$/.test(host)) {
    const octets = host.split('.').map(Number)
    if (octets.length !== 4 || octets.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return false
    const [a, b, c] = octets
    return a !== 0 && a !== 10 && a !== 127 && a! < 224 && !(a === 100 && b! >= 64 && b! < 128) && !(a === 169 && b === 254) && !(a === 172 && b! >= 16 && b! < 32) && !(a === 192 && (b === 168 || b === 0 && (c === 0 || c === 2) || b === 88 && c === 99)) && !(a === 198 && (b === 18 || b === 19 || b === 51 && c === 100)) && !(a === 203 && b === 0 && c === 113)
  }
  const labels = host.split('.')
  return host.length <= 253 && labels.length >= 2 && !/\.(?:localhost|local|internal)$/.test(host) && /[a-z]/i.test(labels.at(-1)!) && labels.every(s => s.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(s))
}
function https(value: unknown): string {
  if (typeof value !== 'string' || value.length > 2048 || !value.startsWith('https://') || /[\x00-\x20\x7f-\uffff\\?#<>"']/.test(value) || /%(?![0-9a-f]{2})/i.test(value) || SECRET.test(value) || value.slice(8).split('/')[0]!.includes('@') || value.slice(8).split('/')[0]!.endsWith(':')) return failure()
  const port = /:([^:\]]*)$/.exec(value.slice(8).split('/')[0]!)?.[1]
  if (port !== undefined && port !== '443') return failure()
  const url = new URL(value)
  const authority = value.slice(8).split('/')[0]!
  const rawHost = authority.startsWith('[') ? authority.slice(0, authority.indexOf(']') + 1) : authority.split(':')[0]!
  // URL normalizes legacy numeric IPv4 and percent-encoded hosts. Require the
  // ordinary raw hostname to agree before that normalization can hide aliases.
  if (!rawHost.startsWith('[') && url.hostname !== rawHost.toLowerCase()) return failure()
  if (url.protocol !== 'https:' || url.username || url.password || url.port && url.port !== '443' || !publicHost(url.hostname)) return failure()
  return value
}
function compare(a: string, b: string): number {
  const x = encoder.encode(a), y = encoder.encode(b)
  for (let i = 0; i < Math.min(x.length, y.length); i++) if (x[i] !== y[i]) return x[i]! - y[i]!
  return x.length - y.length
}
export function parseCreditDocument(bytes: Uint8Array, releaseId: string): CreditDocument {
  const doc = object(parse(bytes, LIMIT), ['format_version', 'release_id', 'mode', 'entries'])
  if (doc.format_version !== 1 || doc.release_id !== releaseId || !HASH.test(releaseId) || doc.mode !== 'synthetic' && doc.mode !== 'production' || !Array.isArray(doc.entries) || doc.entries.length > 256 || doc.mode === 'synthetic' && doc.entries.length !== 0) return failure()
  let previous = ''
  const entries = doc.entries.map(value => {
    const row = object(value, ['name', 'text', 'url'], ['license_url'])
    const credit: DatasetCredit = { name: label(row.name, 128), text: label(row.text, 2048), url: https(row.url) }
    if ('license_url' in row) credit.license_url = https(row.license_url)
    const key = canonical(credit)
    if (previous && compare(previous, key) >= 0) return failure()
    previous = key
    return credit
  })
  return { format_version: 1, release_id: releaseId, mode: doc.mode as CreditDocument['mode'], entries }
}
export function parseCreditIndex(bytes: Uint8Array): CreditIndex {
  const index = object(parse(bytes, 8192), ['format_version', 'current_release_id', 'releases'])
  if (index.format_version !== 1 || typeof index.current_release_id !== 'string' || !HASH.test(index.current_release_id) || !Array.isArray(index.releases) || index.releases.length < 1 || index.releases.length > 2) return failure()
  let previous = ''
  const releases = index.releases.map(value => {
    const row = object(value, ['release_id', 'credits_path', 'credits_sha256'])
    if (typeof row.release_id !== 'string' || !HASH.test(row.release_id) || row.release_id <= previous || typeof row.credits_sha256 !== 'string' || !HASH.test(row.credits_sha256) || row.credits_path !== `/_atlas/credits/${row.credits_sha256}.json`) return failure()
    previous = row.release_id
    return row as CreditRef
  })
  if (!releases.some(row => row.release_id === index.current_release_id)) return failure()
  return { format_version: 1, current_release_id: index.current_release_id, releases }
}
async function fetchBytes(fetcher: typeof fetch, path: string, maximum: number, signal?: AbortSignal): Promise<Uint8Array> {
  const response = await fetcher(path, { cache: path === '/dataset-credits.json' ? 'no-cache' : 'force-cache', credentials: 'omit', referrerPolicy: 'no-referrer', signal })
  if (!response.ok || !response.body || Number(response.headers.get('content-length') ?? 0) > maximum) return failure()
  const reader = response.body.getReader(), chunks: Uint8Array[] = []
  let total = 0
  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      total += value.length
      if (total > maximum || signal?.aborted) return failure()
      chunks.push(value)
    }
  } finally { await reader.cancel() }
  const output = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) { output.set(chunk, offset); offset += chunk.length }
  return output
}
export async function loadDatasetCredits(releaseId?: string, signal?: AbortSignal, fetcher: typeof fetch = globalThis.fetch.bind(globalThis)): Promise<CreditDocument> {
  if (signal?.aborted) return failure()
  const index = parseCreditIndex(await fetchBytes(fetcher, '/dataset-credits.json', 8192, signal))
  const ref = index.releases.find(row => row.release_id === (releaseId ?? index.current_release_id))
  if (!ref) return failure()
  const bytes = await fetchBytes(fetcher, ref.credits_path, LIMIT, signal)
  const hash = [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as BufferSource))].map(b => b.toString(16).padStart(2, '0')).join('')
  if (signal?.aborted || hash !== ref.credits_sha256) return failure()
  return parseCreditDocument(bytes, ref.release_id)
}
