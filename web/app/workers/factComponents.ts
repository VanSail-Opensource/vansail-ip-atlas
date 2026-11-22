// Only verified lookup components are retained. Every key includes the
// immutable source object hash and a selector within that object.
export const COMPONENT_LIMIT = 16 * 1024 * 1024
const ENTRY_LIMIT = 256 * 1024
type Scope = { group: string; bits: number }
type Entry = { value: unknown; bytes: number; scope?: Scope; sourceBytes?: number }

export class FactComponents {
  private entries = new Map<string, Entry>()
  private pinned = new Set<string>()
  private depths = new Map<string, Map<number, number>>()
  bytes = 0
  suspended = false
  private readonly charge?: (hash: string, size: number) => void
  constructor(charge?: (hash: string, size: number) => void) { this.charge = charge }

  get<T>(key: string): T | undefined {
    const entry = this.entries.get(key)
    if (!entry || this.suspended) return undefined
    if (entry.sourceBytes !== undefined) this.charge?.(key.slice(0,64),entry.sourceBytes)
    this.entries.delete(key); this.entries.set(key, entry); this.pinned.add(key)
    return entry.value as T
  }
  put(key: string, value: unknown, payload: number, room: number, scope?: Scope, sourceBytes?: number): boolean {
    if (this.suspended) return false
    const bytes = payload + 320 + key.length * 2 + (scope ? 320 + scope.group.length * 2 : 0)
    if (this.entries.has(key) || bytes > ENTRY_LIMIT || bytes > room) return false
    const limit = Math.min(COMPONENT_LIMIT, room)
    this.trim(limit - bytes)
    if (this.bytes + bytes > limit) return false
    this.entries.set(key, { value, bytes, scope, sourceBytes }); this.bytes += bytes
    this.pinned.add(key)
    if (scope) {
      const counts = this.depths.get(scope.group) ?? new Map<number, number>()
      counts.set(scope.bits, (counts.get(scope.bits) ?? 0) + 1)
      this.depths.set(scope.group, counts)
    }
    return true
  }
  prefix<T>(group: string, hex: string): T | undefined {
    if (this.suspended) return undefined
    const counts = this.depths.get(group)
    if (counts) for (const bits of counts.keys()) {
      const value = this.get<T>(scopeKey(group, hex, bits))
      if (value !== undefined) return value
    }
  }
  trim(maximum: number): void {
    if (this.bytes <= maximum) return
    for (const [key, entry] of this.entries) {
      if (this.pinned.has(key)) continue
      this.entries.delete(key); this.bytes -= entry.bytes
      const scope = entry.scope
      if (scope) {
        const counts = this.depths.get(scope.group)!
        const count = counts.get(scope.bits)! - 1
        if (count) counts.set(scope.bits, count); else counts.delete(scope.bits)
        if (!counts.size) this.depths.delete(scope.group)
      }
      if (this.bytes <= maximum) break
    }
  }
  endQuery(): void { this.pinned.clear() }
  clear(): void { this.entries.clear(); this.depths.clear(); this.pinned.clear(); this.bytes = 0 }
}

export function scopeKey(group: string, hex: string, bits: number): string {
  const whole = Math.floor(bits / 4), partial = bits % 4
  const suffix = partial ? (parseInt(hex[whole]!,16) & (15 << (4 - partial))).toString(16) : ''
  return group + '/' + bits + '/' + hex.slice(0,whole) + suffix
}

type Selected = { key: Uint8Array; row: Uint8Array; prefix: string } | null
type Source = {
  kind: number
  rows(id: number): Uint8Array
  asn(asn: number, run?: boolean): Uint8Array[]
}
type Projection = { sections: Map<number,Uint8Array>; bytes: number }

const u32 = (b: Uint8Array, n: number) => new DataView(b.buffer,b.byteOffset,b.byteLength).getUint32(n,true)
const put = (b: Uint8Array,n: number,v: number) => new DataView(b.buffer,b.byteOffset,b.byteLength).setUint32(n,v,true)
const word16 = (b: Uint8Array, n: number) => b[n]! | b[n + 1]! << 8
const NONE = 0xffffffff

// A candidate cell is safe if no strictly more specific key starts inside
// it in either validated address index. The property is monotone as the cell
// narrows around the address. At host depth the exact/ordinary winner has
// already been selected by the source's own LPM.
export function safePrefixDepth(s: Source, family: number, address: Uint8Array, winner: Selected): number {
  const width = family === 4 ? 32 : 128, offset = family === 4 ? 12 : 0
  const hasChild = (bits: number) => {
    const start = address.slice()
    const byte = offset + (bits >> 3), rem = bits % 8
    if (rem) start[byte] = start[byte]! & (255 << (8 - rem))
    start.fill(0,byte + (rem ? 1 : 0))
    for (const section of [1,8]) {
      const rows = s.rows(section)
      let lo = 0, hi = rows.length / 32
      while (lo < hi) {
        const mid = (lo + hi) >>> 1, pos = mid * 32
        let cmp = rows[pos]! - family
        for (let i = 0; !cmp && i < 16; i++) cmp = rows[pos + 4 + i]! - start[i]!
        if (cmp < 0 || cmp === 0 && rows[pos + 1]! <= bits) lo = mid + 1
        else hi = mid
      }
      const at = lo * 32
      if (at === rows.length || rows[at] !== family) continue
      let matches = true
      for (let i = offset; i < byte && matches; i++) matches = rows[at + 4 + i] === start[i]
      if (matches && (!rem || (rows[at + 4 + byte]! & (255 << (8 - rem))) === start[byte])) return true
    }
    return false
  }
  let lo = winner?.key[1] ?? 0, hi = width
  while (lo < hi) { const mid = (lo + hi) >>> 1; if (hasChild(mid)) lo = mid + 1; else hi = mid }
  return lo
}

// Rebase offsets and external ordinals against compact owned sections. The
// existing field readers can then use the exact same wire representation even
// after the original decoded shard is evicted and its buffers are detached.
class Vectors {
  private chunks = new Map<number, { width:number; rows:Uint8Array[]; bytes:number }>()
  private directory = new Map<number, number>()
  private source: Source
  private bytes = 0
  constructor(source: Source) { this.source = source }
  add(id: number, width: number, data: Uint8Array): number {
    let vector = this.chunks.get(id)
    if (!vector) { vector = {width,rows:[],bytes:0}; this.chunks.set(id,vector) }
    const first = vector.bytes / width
    vector.rows.push(data); vector.bytes += data.length; this.bytes += data.length
    return first
  }
  span(row: Uint8Array, at: number, count: number, id: number, width: number): void {
    const start = u32(row,at)
    put(row,at,this.add(id,width,this.source.rows(id).subarray(start * width,(start + count) * width)))
  }
  ref(row: Uint8Array, at: number): void {
    const old = u32(row,at)
    if (old === NONE) return
    let id = this.directory.get(old)
    if (id === undefined) {
      id = this.add(7,40,this.source.rows(7).subarray(old * 40,old * 40 + 40)); this.directory.set(old,id)
    }
    put(row,at,id)
  }
  finish(): Projection | undefined {
    if (this.bytes > ENTRY_LIMIT) return
    const sections = new Map<number,Uint8Array>()
    let charge = 320
    for (const [id,v] of this.chunks) {
      const data = new Uint8Array(8 + v.bytes)
      put(data,0,v.bytes / v.width); put(data,4,v.width)
      let pos = 8; for (const row of v.rows) { data.set(row,pos); pos += row.length }
      sections.set(id,data); charge += data.length + 256
    }
    return {sections,bytes:charge}
  }
}

export function projectPrefix(s: Source, match: Selected): Projection | undefined {
  const vectors = new Vectors(s)
  if (!match) return vectors.finish()
  const row = match.row.slice(), key = match.key.slice()
  put(key,20,0)
  vectors.add(1,32,key)
  switch (s.kind) {
    case 2: vectors.ref(row,8); vectors.ref(row,16); break
    case 4: vectors.ref(row,16); vectors.ref(row,24); vectors.ref(row,32); vectors.span(row,4,u32(row,8),4,4); break
    case 10: vectors.span(row,4,u32(row,8),4,4); break
    case 3: case 5: case 6: break
    default: return
  }
  vectors.add(3,row.length,row)
  return vectors.finish()
}

export function projectASN(s: Source, asn: number): Projection | undefined {
  const vectors = new Vectors(s), rows = s.asn(asn,true)
  if (!rows.length) return vectors.finish()
  const key = new Uint8Array(8); put(key,0,asn); vectors.add(2,8,key)
  for (const source of rows) {
    const row = source.slice()
    if (s.kind === 8) {
      vectors.ref(row,8); vectors.ref(row,16)
      const first = u32(row,36), count = u32(row,40)
      if (count > 1024) return
      put(row,36,0)
      for (let i = 0; i < count; i++) {
        const page = s.rows(12).slice((first + i) * 16,(first + i + 1) * 16)
        vectors.ref(page,0); vectors.add(12,16,page)
      }
    } else if (s.kind === 11) {
      const first = u32(row,8), count = word16(row,12)
      for (let i = 0; i < count; i++) {
        const seg = s.rows(9).slice((first + i) * 12,(first + i + 1) * 12)
        vectors.span(seg,4,u32(seg,8),4,4)
        const start = vectors.add(9,12,seg)
        if (!i) put(row,8,start)
      }
    } else if (s.kind !== 13) return
    vectors.add(3,row.length,row)
  }
  return vectors.finish()
}
