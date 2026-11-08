// P0 browser contract: native current Chrome APIs, no DNS, no fetch, no polyfill.
export type Input = { kind: 'ip' | 'asn'; canonical: string }
export type Result = {
  state: 'ok' | 'redirect' | 'hero' | 'error'
  route?: string
  q?: string
  kind?: 'ip' | 'asn'
  origin?: string
  query?: string
  error?: string
}

function ipv4(text: string): number[] | null {
  const pieces = text.split('.')
  if (pieces.length !== 4) return null
  const octets: number[] = []
  for (const piece of pieces) {
    if (!/^(0|[1-9][0-9]{0,2})$/.test(piece) || Number(piece) > 255) return null
    octets.push(Number(piece))
  }
  return octets
}

function ip(text: string): string | null {
  if (!text.includes(':')) return ipv4(text)?.join('.') ?? null
  if (!/^[0-9a-fA-F:.]+$/.test(text) || text.includes(':::')) return null
  const halves = text.split('::')
  if (halves.length > 2) return null
  const parse = (half: string): number[] | null => {
    if (half === '') return []
    const pieces = half.split(':')
    const words: number[] = []
    for (let i = 0; i < pieces.length; i++) {
      const piece = pieces[i]!
      if (piece.includes('.')) {
        if (i !== pieces.length - 1 || !text.endsWith(piece)) return null
        const bytes = ipv4(piece)
        if (!bytes) return null
        words.push(bytes[0]! * 256 + bytes[1]!, bytes[2]! * 256 + bytes[3]!)
      } else {
        if (!/^[0-9a-fA-F]{1,4}$/.test(piece)) return null
        words.push(parseInt(piece, 16))
      }
    }
    return words
  }
  const left = parse(halves[0]!)
  const right = halves.length === 2 ? parse(halves[1]!) : []
  if (!left || !right) return null
  const used = left.length + right.length
  if (halves.length === 1 ? used !== 8 : used >= 8) return null
  const words = halves.length === 1 ? left : [...left, ...Array(8 - used).fill(0), ...right]
  if (words.slice(0, 5).every(word => word === 0) && words[5] === 0xffff) {
    return [words[6]! >> 8, words[6]! & 255, words[7]! >> 8, words[7]! & 255].join('.')
  }
  let best = -1
  let bestLength = 1
  for (let i = 0; i < 8;) {
    if (words[i] !== 0) { i++; continue }
    let end = i
    while (end < 8 && words[end] === 0) end++
    if (end - i > bestLength) { best = i; bestLength = end - i }
    i = end
  }
  const hex = words.map(word => word.toString(16))
  return best < 0 ? hex.join(':') : `${hex.slice(0, best).join(':')}::${hex.slice(best + bestLength).join(':')}`
}

export function parseInput(raw: string): Input {
  if (new TextEncoder().encode(raw).byteLength > 128) throw new Error('invalid_input')
  const text = raw.replace(/^[ \t\r\n\f\v]+|[ \t\r\n\f\v]+$/g, '')
  if (text === '' || /[\x00-\x20\x7f%]/.test(text)) throw new Error('invalid_input')
  const address = ip(text)
  if (address !== null) return { kind: 'ip', canonical: address }
  const digits = text.replace(/^AS/i, '')
  if (!/^[0-9]+$/.test(digits)) throw new Error('invalid_input')
  const asn = BigInt(digits)
  if (!((asn >= 1n && asn <= 23455n) || (asn >= 23457n && asn <= 64495n) ||
    (asn >= 131072n && asn <= 4199999999n))) throw new Error('invalid_input')
  return { kind: 'asn', canonical: `AS${asn}` }
}

export function resolve(route: string, raw: string): Result {
  if (!['/ip', '/ip/overview', '/ip/quality', '/ip/class-c', '/ip/bgp', '/ip/asn'].includes(route)) {
    return { state: 'error', error: 'invalid_route' }
  }
  if (new TextEncoder().encode(raw).byteLength > 1024) return { state: 'error', error: 'invalid_query' }
  const values = new Map<string, string>()
  if (raw !== '') {
    for (const part of raw.split('&')) {
      const equal = part.indexOf('=')
      if (equal < 0) return { state: 'error', error: 'invalid_query' }
      try {
        const key = decodeURIComponent(part.slice(0, equal).replace(/\+/g, ' '))
        const value = decodeURIComponent(part.slice(equal + 1).replace(/\+/g, ' '))
        if (!['q', 'origin'].includes(key) || values.has(key) || value === '') {
          return { state: 'error', error: 'invalid_query' }
        }
        values.set(key, value)
      } catch { return { state: 'error', error: 'invalid_query' } }
    }
  }
  const q = values.get('q')
  if (q === undefined) {
    if (values.has('origin')) return { state: 'error', error: 'invalid_query' }
    return { state: route === '/ip' ? 'hero' : 'redirect', route: '/ip' }
  }
  let input: Input
  try { input = parseInput(q) } catch { return { state: 'error', error: 'invalid_input' } }
  let origin: string | undefined
  if (values.has('origin')) {
    if (route !== '/ip/bgp' || input.kind !== 'ip') return { state: 'error', error: 'invalid_origin' }
    try {
      const parsed = parseInput(values.get('origin')!)
      if (parsed.kind !== 'asn') return { state: 'error', error: 'invalid_origin' }
      origin = parsed.canonical
    } catch { return { state: 'error', error: 'invalid_origin' } }
  }
  let state: 'ok' | 'redirect' = 'ok'
  let destination = route
  if (route === '/ip') {
    state = 'redirect'
    destination = input.kind === 'ip' ? '/ip/overview' : '/ip/asn'
  } else if (input.kind === 'asn' && ['/ip/overview', '/ip/quality', '/ip/class-c'].includes(route)) {
    state = 'redirect'
    destination = '/ip/asn'
  }
  let query = `q=${encodeURIComponent(input.canonical)}`
  if (origin !== undefined) query += `&origin=${encodeURIComponent(origin)}`
  return { state, route: destination, q: input.canonical, kind: input.kind,
    ...(origin === undefined ? {} : { origin }), query }
}

export function validateOrigin(requested: number, origins: readonly number[]): void {
  let lo = 0
  let hi = origins.length
  while (lo < hi) {
    const mid = lo + Math.floor((hi - lo) / 2)
    if (origins[mid]! < requested) lo = mid + 1
    else hi = mid
  }
  if (lo === origins.length || origins[lo] !== requested) throw new Error('origin_not_member')
}
