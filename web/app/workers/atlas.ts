import { decodeZstd } from '../lib/zstd.ts'
import { parseInput } from '../lib/query.ts'
import type { Input } from '../lib/query.ts'
import type { LookupAnswer, ClassCAnswer, ASNAnswer, BGPAnswer, ASNPrefixPage } from '../lib/via3.ts'

const MAX_FILE = 24 * 1024 * 1024
const MAX_SECTION = 64 * 1024 * 1024
const MAX_TOTAL = 256 * 1024 * 1024
const PUBLIC_OBJECT = 32 * 1024 * 1024
const PUBLIC_LIVE = 96 * 1024 * 1024
const PUBLIC_ANSWER = 8 * 1024 * 1024
const PUBLIC_ORIGINS = 4096
const PUBLIC_PATH_ASNS = 49152
const NONE = 0xffffffff
const fail = (code: string): never => { throw new Error(code) }
const view = (b: Uint8Array) => new DataView(b.buffer, b.byteOffset, b.byteLength)
const u16 = (b: Uint8Array, p: number) => view(b).getUint16(p, true)
const u32 = (b: Uint8Array, p: number) => view(b).getUint32(p, true)
const i32 = (b: Uint8Array, p: number) => view(b).getInt32(p, true)
const u64 = (b: Uint8Array, p: number, limit: number) => {
  const value = view(b).getBigUint64(p, true)
  if (value > BigInt(limit)) return fail('bounds')
  return Number(value)
}
const zero = (b: Uint8Array) => b.every(value => value === 0)
const mask = (...bits: number[]) => bits.reduce((value, bit) => (value | (1 << bit)) >>> 0, 0)
const has = (b: Uint8Array, bit: number) => (u32(b, 0) & (1 << bit)) !== 0
const range = (first: number, count: number, total: number) => first <= total && count <= total - first
const checkAbort = (signal?: AbortSignal) => { if (signal?.aborted) throw new DOMException('Aborted', 'AbortError') }
const hex = (b: Uint8Array) => Array.from(b, value => value.toString(16).padStart(2, '0')).join('')
const unhex = (text: string) => Uint8Array.from(text.match(/../g) ?? [], part => parseInt(part, 16))
export const hash = async (b: Uint8Array) => hex(new Uint8Array(await crypto.subtle.digest('SHA-256', b as BufferSource)))
const textDecoder = new TextDecoder('utf-8', { fatal: true })
const reasonNames = ['malware', 'botnet', 'command_control', 'abuse', 'fraud', 'scanning', 'spam', 'tor', 'vpn', 'proxy', 'datacenter', 'hosting', 'asn_context', 'subnet_context']
const reasons = (bits: number) => reasonNames.filter((_, bit) => (bits & (1 << bit)) !== 0)
const confidence = (value: number) => ['unrated', 'low', 'medium', 'high'][value]!
const usage = (value: number) => ['unknown', 'residential', 'business', 'mobile', 'datacenter', 'hosting', 'education', 'government'][value]!
const networkClass = (value: number) => ['unknown', 'tier1_candidate', 'global_transit', 'regional_transit', 'access_network'][value]!
const stability = (value: number) => ['unavailable', 'pending', 'stable'][value]!
class AnswerBudget {
  private bytes = 1024
  private paths = 0
  private origins = 0
  charge(bytes: number): void { if (bytes < 0 || bytes > PUBLIC_ANSWER - this.bytes) fail('resource_limit'); this.bytes += bytes }
  path(count: number): void { if (count > PUBLIC_PATH_ASNS - this.paths) fail('resource_limit'); this.paths += count; this.charge(count * 16 + 128) }
  cellOrigins(count: number): void { if (count > PUBLIC_ORIGINS - this.origins) fail('resource_limit'); this.origins += count; this.charge(count * 16) }
}
const answerFits = (value: unknown) => { if (new TextEncoder().encode(JSON.stringify(value)).byteLength > PUBLIC_ANSWER) fail('resource_limit') }
const country = (value: number) => value === 0 ? null : String.fromCharCode(65 + Math.floor((value - 1) / 26), 65 + (value - 1) % 26)
const countryCodes = new Set('AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW'.split(' '))
const publicASN = (value: number) => Number.isInteger(value) && ((value >= 1 && value <= 23455) || (value >= 23457 && value <= 64495) || (value >= 131072 && value <= 4199999999))
const unsafeLabelToken = (value: string) => /[@:/\\]/u.test(value) || /(?:[\p{L}\p{N}-]+\.)+[\p{L}][\p{L}\p{N}-]{1,62}/u.test(value.replace(/^[.,;!()[\]{}"']+|[.,;!()[\]{}"']+$/g, ''))
function validPartition(value: string): boolean {
  if (value === 'all') return true
  if (value.startsWith('asn:')) {
    const parts = value.split(':'); const first = Number(parts[1]); const last = Number(parts[2])
    return parts.length === 3 && String(first) === parts[1] && String(last) === parts[2] && publicASN(first) && publicASN(last) && first <= last && !(first <= 23456 && last >= 23456) && !(first <= 131071 && last >= 64496)
  }
  if (!/^[46]:[0-9a-f]{32}\/[0-9]{1,3}$/.test(value)) return false
  const [address, bits] = value.slice(2).split('/'); const length = Number(bits)
  if (String(length) !== bits || length < 0 || length > 128) return false
  const key = new Uint8Array(32); key[0] = value[0] === '4' ? 4 : 6; key[1] = length; key.set(unhex(address!), 4)
  return validKey(key)
}

function schema(kind: number): { width: number; sections: number[] } {
  const widths = [0, 16, 24, 16, 40, 8, 32, 24, 64, 16, 16, 24, 16, 16, 0]
  const sections = [[], [1, 2, 3, 4, 7], [1, 3, 7, 8], [1, 3, 8], [1, 3, 4, 7, 8], [1, 3, 8], [1, 3, 8], [1, 3, 7, 10], [2, 3, 7, 11, 12], [1, 3, 8], [1, 3, 4, 8], [2, 3, 4, 9], [2, 3, 4], [2, 3], [5, 6]]
  if (kind < 1 || kind > 14) return fail('schema')
  return { width: widths[kind]!, sections: sections[kind]! }
}
const sectionWidth = (id: number, recordWidth: number) => [0, 32, 8, recordWidth, 4, 4, 1, 40, 32, 12, 32, 24, 16][id]!
function compareKey(a: Uint8Array, b: Uint8Array): number {
  if (a[0] !== b[0]) return a[0]! - b[0]!
  for (let p = 4; p < 20; p++) if (a[p] !== b[p]) return a[p]! - b[p]!
  if (a[1] !== b[1]) return a[1]! - b[1]!
  return u16(a, 2) - u16(b, 2)
}
function validKey(row: Uint8Array): boolean {
  const width = row[0] === 4 ? 32 : row[0] === 6 ? 128 : 0
  if (width === 0 || row[1]! > width || u16(row, 2) > 1 || (row.length >= 32 && !zero(row.subarray(24, 32)))) return false
  if (width === 32 && !zero(row.subarray(4, 16))) return false
  if (width === 128 && zero(row.subarray(4, 14)) && row[14] === 255 && row[15] === 255) return false
  if (u16(row, 2) === 1 && row[1] !== width) return false
  const offset = width === 32 ? 16 : 4
  for (let bit = row[1]!; bit < width; bit++) if ((row[offset + Math.floor(bit / 8)]! & (1 << (7 - bit % 8))) !== 0) return false
  return true
}
function addressBytes(canonical: string): { family: number; bytes: Uint8Array } {
  const bytes = new Uint8Array(16)
  if (!canonical.includes(':')) { bytes.set(canonical.split('.').map(Number), 12); return { family: 4, bytes } }
  const halves = canonical.split('::')
  const left = halves[0] ? halves[0].split(':').map(word => parseInt(word, 16)) : []
  const right = halves.length === 2 && halves[1] ? halves[1].split(':').map(word => parseInt(word, 16)) : []
  const words = halves.length === 1 ? left : [...left, ...Array<number>(8 - left.length - right.length).fill(0), ...right]
  words.forEach((word, index) => { bytes[index * 2] = word >> 8; bytes[index * 2 + 1] = word & 255 })
  return { family: 6, bytes }
}
function keyFor(canonical: string, length: number, exact: boolean): Uint8Array {
  const { family, bytes } = addressBytes(canonical)
  const width = family === 4 ? 32 : 128
  const row = new Uint8Array(32)
  row[0] = family; row[1] = length; row[2] = exact ? 1 : 0
  row.set(bytes, 4)
  const offset = family === 4 ? 16 : 4
  for (let bit = length; bit < width; bit++) row[offset + Math.floor(bit / 8)]! &= ~(1 << (7 - bit % 8))
  return row
}
function prefixText(key: Uint8Array): string {
  const address = key[0] === 4 ? Array.from(key.subarray(16, 20)).join('.') : parseInput(Array.from({ length: 8 }, (_, index) => (key[4 + index * 2]! * 256 + key[5 + index * 2]!).toString(16)).join(':')).canonical
  return `${address}/${key[1]}`
}

export class Shard {
  readonly kind: number
  readonly sections: Map<number, Uint8Array>
  constructor(kind: number, sections: Map<number, Uint8Array>) { this.kind = kind; this.sections = sections }
  rows(id: number): Uint8Array { return this.sections.get(id)?.subarray(8) ?? new Uint8Array() }
  width(id: number): number { const section = this.sections.get(id); return section ? u32(section, 4) : 0 }
  record(index: number): Uint8Array { const rows = this.rows(3); const width = this.width(3); if (!width || index < 0 || index >= rows.length / width) return fail('record'); return rows.subarray(index * width, (index + 1) * width) }
  prefix(canonical: string): { row: Uint8Array; prefix: string; key: Uint8Array } | null {
    const width = canonical.includes(':') ? 128 : 32
    for (let length = width; length >= 0; length--) {
      for (const exact of length === width ? [true, false] : [false]) {
        const target = keyFor(canonical, length, exact)
        for (const id of [1, 8]) {
          const rows = this.rows(id)
          let lo = 0; let hi = rows.length / 32
          while (lo < hi) { const mid = lo + Math.floor((hi - lo) / 2); if (compareKey(rows.subarray(mid * 32, (mid + 1) * 32), target) < 0) lo = mid + 1; else hi = mid }
          if (lo < rows.length / 32) { const key = rows.subarray(lo * 32, (lo + 1) * 32); if (compareKey(key, target) === 0) return { row: this.record(u32(key, 20)), prefix: prefixText(key), key } }
        }
      }
    }
    return null
  }
  asn(asn: number, run = false): Uint8Array[] {
    const bounds = this.asnBounds(asn)
    if (!bounds) return []
    const [first, end] = bounds
    if (run && (this.kind === 12 || (this.kind === 11 && end - first > 12) || ((this.kind === 8 || this.kind === 13) && end - first > 1))) return fail('record')
    return Array.from({ length: run ? end - first : 1 }, (_, index) => this.record(first + index))
  }
  private asnBounds(asn: number): [number, number] | null {
    const rows = this.rows(2)
    let lo = 0; let hi = rows.length / 8
    while (lo < hi) { const mid = lo + Math.floor((hi - lo) / 2); if (u32(rows, mid * 8) < asn) lo = mid + 1; else hi = mid }
    if (lo === rows.length / 8 || u32(rows, lo * 8) !== asn) return null
    const first = u32(rows, lo * 8 + 4)
    const end = lo + 1 < rows.length / 8 ? u32(rows, (lo + 1) * 8 + 4) : this.rows(3).length / this.width(3)
    return [first, end]
  }
  relationship(from: number, to: number): Uint8Array | null {
    const bounds = this.asnBounds(from); if (!bounds) return null
    const [first, end] = bounds; let lo = first; let hi = end
    while (lo < hi) { const mid = lo + Math.floor((hi - lo) / 2); if (u32(this.record(mid), 8) < to) lo = mid + 1; else hi = mid }
    return lo < end && u32(this.record(lo), 8) === to ? this.record(lo) : null
  }
  rpki(canonical: string, origin: number, announcement: string | null): Uint8Array | null {
    const width = canonical.includes(':') ? 128 : 32
    if (!announcement) return null
    const parts = announcement.split('/'); const length = Number(parts[1])
    if (parts.length !== 2 || !Number.isInteger(length) || length < 0 || length > width) return null
    // Match the selected actual announcement directly. Other, more-specific
    // announcements must neither hide its result nor lend it their status.
    const target = keyFor(canonical, length, false)
    if (prefixText(target) !== announcement) return null
    for (const id of [1, 8]) {
      const index = this.rows(id); const count = index.length / 32; let lo = 0; let hi = count
      while (lo < hi) { const mid = lo + Math.floor((hi - lo) / 2); if (compareKey(index.subarray(mid * 32, (mid + 1) * 32), target) < 0) lo = mid + 1; else hi = mid }
      const first = lo
      if (first === count || compareKey(index.subarray(first * 32, (first + 1) * 32), target) !== 0) continue
      hi = count
      while (lo < hi) { const mid = lo + Math.floor((hi - lo) / 2); if (compareKey(index.subarray(mid * 32, (mid + 1) * 32), target) <= 0) lo = mid + 1; else hi = mid }
      const end = lo; lo = first; hi = end
      while (lo < hi) { const mid = lo + Math.floor((hi - lo) / 2); if (u32(this.record(u32(index, mid * 32 + 20)), 4) < origin) lo = mid + 1; else hi = mid }
      if (lo === end) return null
      const row = this.record(u32(index, lo * 32 + 20)); return u32(row, 4) === origin ? row : null
    }
    return null
  }
}

function validate(shard: Shard): void {
  const { width, sections } = schema(shard.kind)
  if (shard.sections.size !== sections.length) fail('schema')
  for (const id of sections) { const bytes = shard.sections.get(id); if (!bytes || bytes.length < 8 || u32(bytes, 4) !== sectionWidth(id, width) || u32(bytes, 0) * u32(bytes, 4) !== bytes.length - 8) fail('schema') }
  const records = shard.rows(3); const count = width === 0 ? 0 : records.length / width
  const objects = shard.rows(7); const ints = shard.rows(4); const pages = shard.rows(12); const segments = shard.rows(9); const cells = shard.rows(10)
  for (let p = 0; p < objects.length; p += 40) {
    const kind = u16(objects, p)
    if (kind < 1 || kind > 14 || u16(objects, p + 2) !== 0 || u32(objects, p + 4) < 64 || u32(objects, p + 4) >= MAX_FILE) fail('record')
    if (p && (u16(objects, p - 40) > kind || (u16(objects, p - 40) === kind && hex(objects.subarray(p - 32, p)) >= hex(objects.subarray(p + 8, p + 40))))) fail('record')
  }
  const ref = (row: Uint8Array, p: number, bit: number, kind: number) => {
    const object = u32(row, p); const id = u32(row, p + 4)
    return has(row, bit) ? object !== NONE && id !== NONE && object < objects.length / 40 && u16(objects, object * 40) === kind : object === NONE && id === NONE
  }
  const asns = (first: number, total: number) => {
    if (!range(first, total, ints.length / 4)) return false
    for (let index = 0; index < total; index++) if (u32(ints, (first + index) * 4) === 0 || (index > 0 && u32(ints, (first + index - 1) * 4) >= u32(ints, (first + index) * 4))) return false
    return true
  }
  for (const id of [1, 8]) {
    const index = shard.rows(id)
    for (let p = 0; p < index.length; p += 32) {
      const key = index.subarray(p, p + 32)
      if (!validKey(key) || u32(key, 20) >= count || (shard.kind === 7 && (key[0] !== 4 || key[1] !== 24 || u16(key, 2) !== 0))) fail('record')
      if ((shard.kind === 9 || shard.kind === 10) && u16(key, 2) !== 0) fail('record')
      if (shard.kind === 6 && key[0] === 6) { const row = shard.record(u32(key, 20)); if (has(row, 9) || has(row, 13)) fail('record') }
      if (shard.kind === 9) { const row = shard.record(u32(key, 20)); if (row[9]! > (key[0] === 4 ? 32 : 128) || (row[8] === 1 && row[9]! < key[1]!) || ((row[8] === 0 || row[8] === 3) && row[9] !== 0)) fail('record') }
      if (p) { const comparison = compareKey(index.subarray(p - 32, p), key); if (comparison > 0 || (comparison === 0 && (shard.kind !== 9 || u32(shard.record(u32(index, p - 12)), 4) >= u32(shard.record(u32(key, 20)), 4)))) fail('record') }
    }
  }
  const local = shard.rows(1); const overlay = shard.rows(8)
  for (let p = 0; p < overlay.length; p += 32) { let lo = 0; let hi = local.length / 32; const key = overlay.subarray(p, p + 32); while (lo < hi) { const mid = lo + Math.floor((hi - lo) / 2); if (compareKey(local.subarray(mid * 32, (mid + 1) * 32), key) < 0) lo = mid + 1; else hi = mid }; if (lo < local.length / 32 && compareKey(local.subarray(lo * 32, (lo + 1) * 32), key) === 0) fail('record') }
  const index = shard.rows(2)
  for (let p = 0; p < index.length; p += 8) {
    if (u32(index, p) === 0 || u32(index, p + 4) >= count || (p > 0 && (u32(index, p - 8) >= u32(index, p) || u32(index, p - 4) > u32(index, p + 4) || (shard.kind !== 1 && u32(index, p - 4) === u32(index, p + 4))))) fail('record')
    if (shard.kind === 8 || shard.kind >= 11) {
      const first = u32(index, p + 4); const end = p + 8 < index.length ? u32(index, p + 12) : count
      if (first >= end || end > count || (p === 0 && first !== 0) || (shard.kind === 11 && end - first > 12) || ((shard.kind === 8 || shard.kind === 13) && end - first !== 1)) fail('record')
      let previousTo = 0
      for (let j = first; j < end; j++) { const row = shard.record(j); if (u32(row, 4) !== u32(index, p)) fail('record'); if (shard.kind === 12) { if (j > first && u32(row, 8) <= previousTo) fail('record'); previousTo = u32(row, 8) } }
    }
  }
  if ((shard.kind === 8 || shard.kind >= 11) && count > 0 && index.length === 0) fail('record')
  const allowed = [0, 0, mask(0, 1, 2, 3), mask(4), mask(15, 16, 17, 18, 19), mask(5, 6, 7, 8), mask(9, 10, 11, 12, 13, 14), mask(21, 22), mask(14, 16, 17, 23, 24, 25, 26, 27, 28, 31), mask(20), mask(19), mask(29), mask(30), mask(27, 28)]
  for (let p = 0; p < records.length; p += width) {
    const row = records.subarray(p, p + width)
    if (shard.kind !== 1 && (u32(row, 0) & ~allowed[shard.kind]!) !== 0) fail('record')
    switch (shard.kind) {
      case 1: {
        if (!zero(row.subarray(6)) || !range(u32(row, 0), u16(row, 4), ints.length / 4)) fail('record')
        let previous = 0
        for (let j = 0; j < u16(row, 4); j++) { const object = u32(ints, (u32(row, 0) + j) * 4); if (object >= objects.length / 40) fail('record'); const kind = u16(objects, object * 40); if (kind === 1 || kind <= previous) fail('record'); previous = kind }
        break
      }
      case 2:
        for (const [bit, position] of [[0, 4], [1, 6]]) { const value = u16(row, position!); if (has(row, bit!) ? value === 0 || value > 676 || !countryCodes.has(country(value)!) : value !== 0) fail('record') }
        if (!ref(row, 8, 2, 14) || !ref(row, 16, 3, 14)) fail('record')
        break
      case 3:
        if (Math.abs(i32(row, 4)) > 90000 || Math.abs(i32(row, 8)) > 180000 || row[12]! > 4 || !zero(row.subarray(13)) || (!has(row, 4) && !zero(row.subarray(4, 13))) || (has(row, 4) && row[12] === 0)) fail('record')
        break
      case 4:
        if (!zero(row.subarray(12, 16)) || !ref(row, 16, 16, 14) || !ref(row, 24, 17, 14) || !ref(row, 32, 18, 14) || !asns(u32(row, 4), u32(row, 8)) || (!has(row, 19) && (u32(row, 4) !== 0 || u32(row, 8) !== 0))) fail('record')
        if (u32(row, 8) > PUBLIC_ORIGINS) fail('resource_limit')
        break
      case 5:
        if (row[4]! > 7 || row[5]! > 2 || row[6]! > 3 || row[7] !== 0 || (!has(row, 5) && row[4] !== 0) || (!has(row, 6) && row[5] !== 0) || (!has(row, 7) && (row[6]! & 1) !== 0) || (!has(row, 8) && (row[6]! & 2) !== 0)) fail('record')
        break
      case 6:
        if (u32(row, 4) > 0x3fff || row[8]! > 1 || row[9]! > 100 || row[10]! > 3 || row[11] !== 0 || !zero(row.subarray(28)) || (!has(row, 14) && u32(row, 4) !== 0) || (row[8] === 1) !== has(row, 9) || (!has(row, 9) && (row[9] !== 0 || row[10] !== 0)) || (row[8] === 1 && (row[10] === 0 || (u32(row, 0) & mask(10, 11, 12, 13)) !== mask(10, 11, 12, 13)))) fail('record')
        for (const [index, cap] of [550000, 180000, 150000, 120000].entries()) if (u32(row, 12 + index * 4) > cap || (!has(row, 10 + index) && u32(row, 12 + index * 4) !== 0)) fail('record')
        if (has(row, 9)) { const sum = u32(row, 12) + u32(row, 16) + u32(row, 20) + u32(row, 24); const lowScore = Math.floor((1000000 - Math.min(1000000, sum + 2) + 5000) / 10000); const highScore = Math.floor((1000000 - Math.max(0, sum - 2) + 5000) / 10000); if (row[9]! < lowScore || row[9]! > highScore) fail('record') }
        break
      case 7: {
        const first = u32(row, 4); const count = u16(row, 8)
        if (!range(first, count, cells.length / 32) || count > 256 || u16(row, 10) > count || u16(row, 12) > count || !zero(row.subarray(14, 16)) || !zero(row.subarray(22)) || row[20]! > 100 || row[21]! > 3 || (has(row, 22) ? count !== 256 || u16(row, 10) !== 256 || row[21] === 0 : row[20] !== 0 || row[21] !== 0)) fail('record')
        let previous = -1; let assessed = 0; let positive = 0
        for (let j = first; j < first + count; j++) {
          const c = cells.subarray(j * 32, (j + 1) * 32)
          if (c[0]! <= previous || c[2]! > 7 || c[3]! > 2 || u32(c, 4) > 0x3fff || c[8]! > 100 || c[9]! > 3 || u16(c, 10) !== 0 || u32(c, 12) > 1000000 || c[24]! > 3 || !zero(c.subarray(25))) fail('record')
          previous = c[0]!
          if (c[1]! & 8) { if (c[9] === 0) fail('record'); assessed++ } else if (c[8] !== 0 || c[9] !== 0) fail('record')
          if (u32(c, 4)) positive++
          for (const [bit, position, size] of [[0, 2, 1], [1, 3, 1], [2, 4, 4], [4, 12, 4]]) if (!(c[1]! & (1 << bit!)) && !zero(c.subarray(position!, position! + size!))) fail('record')
          const a = u32(c, 16); const b = u32(c, 20)
          if (c[1]! & 32 ? a === NONE || b === NONE || a >= objects.length / 40 || u16(objects, a * 40) !== 4 : a !== NONE || b !== NONE) fail('record')
          if (!(c[1]! & 64) && (c[24]! & 1) || !(c[1]! & 128) && (c[24]! & 2)) fail('record')
        }
        if (assessed !== u16(row, 10) || positive !== u16(row, 12)) fail('record')
        break
      }
      case 8:
        if (!ref(row, 8, 16, 14) || !ref(row, 16, 17, 14) || u16(row, 24) > 676 || row[26]! > 3 || row[27]! > 3 || u32(row, 28) > 1000000 || u32(row, 32) > 0x3fff || row[52]! > 4 || row[53]! > 2 || !zero(row.subarray(54)) || !range(u32(row, 36), u32(row, 40), pages.length / 16) || (!has(row, 23) && !zero(row.subarray(26, 32))) || (!has(row, 31) && u16(row, 24) !== 0)) fail('record')
        for (const [bit, position, size] of [[14, 32, 4], [24, 36, 8], [25, 44, 4], [26, 48, 4], [27, 52, 1], [28, 53, 1]]) if (!has(row, bit!) && !zero(row.subarray(position!, position! + size!))) fail('record')
        if (has(row, 31) && !countryCodes.has(country(u16(row, 24))!)) fail('record')
        if (has(row, 23) && row[26] !== (u32(row, 28) >= 666667 ? 3 : u32(row, 28) >= 333334 ? 2 : 1)) fail('record')
        break
      case 9:
        if (!u32(row, 4) || row[8]! > 3 || row[9]! > 128 || !zero(row.subarray(10)) || (!has(row, 20) && (row[8] !== 0 || row[9] !== 0))) fail('record')
        break
      case 10: if (!zero(row.subarray(12)) || !asns(u32(row, 4), u32(row, 8)) || (!has(row, 19) && (u32(row, 4) !== 0 || u32(row, 8) !== 0))) fail('record'); if (u32(row, 8) > PUBLIC_ORIGINS) fail('resource_limit'); break
      case 11: {
        if (!u32(row, 4) || !has(row, 29) || u16(row, 12) === 0 || u16(row, 12) > 255 || row[14]! > 1 || row[15]! > 3 || !zero(row.subarray(16)) || !range(u32(row, 8), u16(row, 12), segments.length / 12)) fail('record')
        let total = 0
        const seen = new Set<number>(); let previous = 0
        for (let j = u32(row, 8); j < u32(row, 8) + u16(row, 12); j++) {
          const seg = segments.subarray(j * 12, (j + 1) * 12); if (seg[0]! < 1 || seg[0]! > 4 || !zero(seg.subarray(1, 4)) || !u32(seg, 8) || !range(u32(seg, 4), u32(seg, 8), ints.length / 4) || ((row[14]! & 1) && seg[0] !== 1) || ((seg[0] === 2 || seg[0] === 4) && !asns(u32(seg, 4), u32(seg, 8)))) fail('record')
          for (let k = 0; k < u32(seg, 8); k++) { const asn = u32(ints, (u32(seg, 4) + k) * 4); if (!asn) fail('record'); if (row[14]! & 1) { if (!publicASN(asn) || (total === 0 && k === 0 && asn !== u32(row, 4)) || (asn !== previous && seen.has(asn))) fail('record'); seen.add(asn); previous = asn } }
          total += u32(seg, 8)
        }
        if (total > 4096) fail('record')
        break
      }
      case 12: if (!has(row, 30) || !u32(row, 4) || !u32(row, 8) || u32(row, 4) === u32(row, 8) || row[12]! > 4 || row[13]! > 3 || u16(row, 14) || (row[12] !== 0 && !(row[13]! & 2))) fail('record'); break
      case 13: if (!u32(row, 4) || row[8]! > 4 || row[9]! > 2 || !zero(row.subarray(10)) || (row[8] === 1 && row[9] !== 2) || (!has(row, 27) && row[8] !== 0) || (!has(row, 28) && row[9] !== 0)) fail('record'); break
    }
  }
  for (let p = 0; p < pages.length; p += 16) if (u32(pages, p) >= objects.length / 40 || u16(objects, u32(pages, p) * 40) !== 8 || !u32(pages, p + 8) || u32(pages, p + 8) > 256 || u32(pages, p + 12)) fail('record')
  const prefixes = shard.rows(11)
  for (let p = 0; p < prefixes.length; p += 24) { const key = prefixes.subarray(p, p + 24); if (!validKey(key) || u16(key, 2) || u32(key, 20) || (p > 0 && compareKey(prefixes.subarray(p - 24, p), key) >= 0)) fail('record') }
  if (shard.kind === 14) {
    const offsets = shard.rows(5); const bytes = shard.rows(6)
    if (offsets.length < 4 || u32(offsets, 0) !== 0 || u32(offsets, offsets.length - 4) !== bytes.length) fail('record')
    let previous = ''
    for (let p = 0; p < offsets.length - 4; p += 4) {
      const a = u32(offsets, p); const b = u32(offsets, p + 4)
      if (a >= b || b > bytes.length || b - a > 256) fail('record')
      let label: string
      try { label = textDecoder.decode(bytes.subarray(a, b)) } catch { return fail('record') }
      if (label.normalize('NFC') !== label || label.trim() !== label || /[\p{Cc}\p{Cf}]/u.test(label) || label.split(/\s/u).some(unsafeLabelToken) || (p > 0 && hex(bytes.subarray(u32(offsets, p - 4), a)) >= hex(bytes.subarray(a, b)))) fail('record')
      previous = label
    }
    void previous
  }
}

export async function parseShard(bytes: Uint8Array, signal?: AbortSignal): Promise<Shard> {
  checkAbort(signal)
  if (bytes.length < 64 || bytes.length >= MAX_FILE) return fail('length')
  if (bytes[0] !== 86 || bytes[1] !== 73 || bytes[2] !== 65 || bytes[3] !== 51 || u16(bytes, 4) !== 3 || u16(bytes, 6) !== 3) return fail('version')
  if (u16(bytes, 8) !== 64 || u32(bytes, 12) !== 0 || bytes[44] !== 1 || !zero(bytes.subarray(45, 64))) return fail('header')
  if (view(bytes).getBigUint64(36, true) > BigInt(PUBLIC_OBJECT)) return fail('resource_limit')
  const kind = u16(bytes, 10); const expected = schema(kind)
  const count = u32(bytes, 16)
  if (!count || count > 256 || u64(bytes, 20, MAX_FILE) !== 64 || u64(bytes, 28, MAX_FILE) !== bytes.length || u64(bytes, 36, MAX_TOTAL) > MAX_TOTAL) return fail('bounds')
  let end = 64 + count * 64; let total = 0; let previous = 0
  if (end > bytes.length) return fail('bounds')
  if (count !== expected.sections.length) return fail('schema')
  const descriptors: { id: number; offset: number; length: number; decoded: number; hash: string }[] = []
  for (let index = 0; index < count; index++) {
    const descriptor = bytes.subarray(64 + index * 64, 128 + index * 64)
    const id = u16(descriptor, 0); const offset = u64(descriptor, 8, MAX_FILE); const length = u64(descriptor, 16, MAX_FILE); const decoded = u64(descriptor, 24, MAX_SECTION)
    if (id <= previous || descriptor[2] !== 1 || descriptor[3] !== 0 || !zero(descriptor.subarray(4, 8)) || id !== expected.sections[index]) return fail('schema')
    if (offset !== end || !length || length > bytes.length - end || decoded > MAX_TOTAL - total) return fail('bounds')
    previous = id; end += length; total += decoded
    descriptors.push({ id, offset, length, decoded, hash: hex(descriptor.subarray(32, 64)) })
  }
  if (end !== bytes.length || total !== u64(bytes, 36, MAX_TOTAL)) return fail('bounds')
  const sections = new Map<number, Uint8Array>()
  for (const descriptor of descriptors) {
    checkAbort(signal)
    let decoded: Uint8Array
    try { decoded = await decodeZstd(bytes.subarray(descriptor.offset, descriptor.offset + descriptor.length), descriptor.decoded) } catch (error) { const code = (error as { code?: string }).code; return fail(code === 'limit' ? 'decompression_limit' : code === 'integrity' ? 'integrity' : 'codec') }
    if (decoded.length !== descriptor.decoded || await hash(decoded) !== descriptor.hash) return fail('integrity')
    sections.set(descriptor.id, decoded)
  }
  checkAbort(signal)
  const shard = new Shard(kind, sections)
  validate(shard)
  return shard
}

type ObjectInfo = { bytes: number; kind: number; partition: string; sha256: string }
type Manifest = { codec: string; format_version: number; mode: 'synthetic' | 'production'; objects: ObjectInfo[]; release_id: string; schema_version: number; valid_from: number; valid_until: number }
type Pointer = { format_version: number; manifest_path: string; manifest_sha256: string; release_id: string }
const exactKeys = (value: object, keys: string[]) => Object.keys(value).sort().join(',') === keys.sort().join(',')
function canonical(value: unknown): string {
  if (value === null || typeof value === 'boolean') return JSON.stringify(value)
  if (typeof value === 'number') { if (!Number.isSafeInteger(value)) return fail('manifest'); return JSON.stringify(value) }
  if (typeof value === 'string') { if (value.normalize('NFC') !== value) return fail('manifest'); return JSON.stringify(value) }
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`
  if (typeof value === 'object') return `{${Object.entries(value).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([key, item]) => `${JSON.stringify(key)}:${canonical(item)}`).join(',')}}`
  return fail('manifest')
}
function parseCanonical<T>(bytes: Uint8Array): T { let text: string; let parsed: unknown; try { text = textDecoder.decode(bytes); parsed = JSON.parse(text) } catch { return fail('manifest') }; if (canonical(parsed) !== text) return fail('manifest'); return parsed as T }

class ObjectCache {
  private database: Promise<IDBDatabase | null> | null = null
  private db(): Promise<IDBDatabase | null> {
    if (typeof indexedDB === 'undefined') return Promise.resolve(null)
    this.database ??= new Promise(resolve => {
      const request = indexedDB.open('via3-schema3', 1)
      request.onupgradeneeded = () => { const db = request.result; db.createObjectStore('objects'); db.createObjectStore('meta', { keyPath: 'hash' }) }
      request.onsuccess = () => resolve(request.result)
      request.onerror = request.onblocked = () => resolve(null)
    })
    return this.database
  }
  async get(key: string, expectedLength: number): Promise<Uint8Array | null> {
    const db = await this.db(); if (!db) return null
    return new Promise((resolve, reject) => {
      const request = db.transaction('objects').objectStore('objects').get(key)
      request.onsuccess = () => {
        if (request.result === undefined) { resolve(null); return }
        if (!(request.result instanceof ArrayBuffer) || request.result.byteLength < 64 || request.result.byteLength >= MAX_FILE || request.result.byteLength !== expectedLength) {
          this.evictFrom(db, key); reject(new Error('integrity')); return
        }
        resolve(new Uint8Array(request.result))
      }
      request.onerror = () => resolve(null)
    })
  }
  private evictFrom(db: IDBDatabase, key: string): void { try { const transaction = db.transaction(['objects', 'meta'], 'readwrite'); transaction.objectStore('objects').delete(key); transaction.objectStore('meta').delete(key) } catch { /* Cache failure cannot publish unverified bytes. */ } }
  async evict(key: string): Promise<void> { const db = await this.db(); if (db) this.evictFrom(db, key) }
  async put(key: string, bytes: Uint8Array): Promise<void> {
    const db = await this.db(); if (!db) return
    await new Promise<void>(resolve => {
      const transaction = db.transaction(['objects', 'meta'], 'readwrite'); const meta = transaction.objectStore('meta'); const objects = transaction.objectStore('objects')
      const write = () => { objects.put(bytes.byteOffset === 0 && bytes.buffer instanceof ArrayBuffer && bytes.byteLength === bytes.buffer.byteLength ? bytes.buffer : bytes.slice().buffer, key); meta.put({ hash: key, size: bytes.length, used: Date.now() }) }
      const count = meta.count()
      count.onsuccess = () => {
        if (count.result > 18500) { meta.clear(); objects.clear(); write(); return }
        const request = meta.getAll(undefined, 18500)
        request.onsuccess = () => {
        const stored = request.result as { hash: string; size: number; used: number }[]
        if (stored.some(row => !row || !exactKeys(row, ['hash', 'size', 'used']) || !/^[0-9a-f]{64}$/.test(row.hash) || !Number.isSafeInteger(row.size) || row.size < 64 || row.size >= MAX_FILE || !Number.isSafeInteger(row.used) || row.used < 0)) { meta.clear(); objects.clear(); write(); return }
        const rows = stored.filter(row => row.hash !== key).sort((a, b) => a.used - b.used)
        let total = rows.reduce((sum, row) => sum + row.size, bytes.length)
        while ((total > 128 * 1024 * 1024 || rows.length >= 18500) && rows.length) { const row = rows.shift()!; total -= row.size; meta.delete(row.hash); objects.delete(row.hash) }
        write()
        }
      }
      transaction.oncomplete = transaction.onerror = transaction.onabort = () => resolve()
    })
  }
}

/** Indexed reader used only in the worker; injected fetch/clock support parity tests. */
export class AtlasReader {
  private fetcher: typeof fetch
  private clock: () => number
  private invalidate: (reason: string) => void
  private leaseClock: () => number
  private manifest: Manifest | null = null
  private pointerHash = ''
  private inventory = new Map<string, ObjectInfo>()
  private cache = new Map<string, Shard>()
  private cacheBytes = 0
  private active = new Map<string, Shard>()
  private activeReserved = new Set<string>()
  private activeBytes = 0
  private routerBytes = 0
  private residents = new Map<string, { size: number; query: boolean; cache: boolean; router: boolean }>()
  private residentBytes = 0
  private router: Shard | null = null
  private persistent = new ObjectCache()
  private expiryTimer: ReturnType<typeof setTimeout> | null = null
  private leaseTimer: ReturnType<typeof setTimeout> | null = null
  private revalidateTimer: ReturnType<typeof setTimeout> | null = null
  private pointerCheckedAt = -Infinity
  private leaseEpoch = 0
  private revalidateController: AbortController | null = null
  constructor(fetcher: typeof fetch = fetch, clock = () => Math.floor(Date.now() / 1000), invalidate: (reason: string) => void = () => {}, leaseClock = () => performance.now() / 1000) { this.fetcher = fetcher.bind(globalThis); this.clock = clock; this.invalidate = invalidate; this.leaseClock = leaseClock }
  clear(): void { this.cache.clear(); this.cacheBytes = 0; this.active.clear(); this.activeReserved.clear(); this.activeBytes = 0; this.routerBytes = 0; this.residents.clear(); this.residentBytes = 0; this.manifest = null; this.router = null; this.inventory.clear(); this.pointerHash = ''; this.pointerCheckedAt = -Infinity; this.leaseEpoch++; this.revalidateController?.abort(); if (this.expiryTimer) clearTimeout(this.expiryTimer); if (this.leaseTimer) clearTimeout(this.leaseTimer); if (this.revalidateTimer) clearTimeout(this.revalidateTimer) }
  private releaseResident(key: string): void { const entry = this.residents.get(key); if (entry && !entry.query && !entry.cache && !entry.router) { this.residentBytes -= entry.size; this.residents.delete(key) } }
  private endQuery(): void { for (const key of this.activeReserved) { const entry = this.residents.get(key); if (entry) { entry.query = false; this.releaseResident(key) } }; this.active.clear(); this.activeReserved.clear(); this.activeBytes = 0 }
  private beginQuery(): void { this.endQuery() }
  private shardBytes(shard: Shard): number { return [...shard.sections.values()].reduce((sum, bytes) => sum + bytes.length, 0) }
  private evictCache(key: string): void { const object = this.cache.get(key); if (object) { this.cacheBytes -= this.shardBytes(object); this.cache.delete(key) }; const entry = this.residents.get(key); if (entry) { entry.cache = false; this.releaseResident(key) } }
  private admit(key: string, size: number): void {
    if (this.activeReserved.has(key)) return
    if (size > PUBLIC_OBJECT) fail('resource_limit')
    let entry = this.residents.get(key)
    if (entry && entry.size !== size) fail('record')
    while (!entry && size > PUBLIC_LIVE - this.residentBytes && this.cache.size) this.evictCache(this.cache.keys().next().value!)
    if (!entry && size > PUBLIC_LIVE - this.residentBytes) fail('resource_limit')
    if (!entry) { entry = { size, query: true, cache: false, router: false }; this.residents.set(key, entry); this.residentBytes += size }
    entry.query = true
    this.activeReserved.add(key); this.activeBytes += size
  }
  private current(): Manifest { const manifest = this.manifest; if (!manifest || this.clock() < manifest.valid_from || this.clock() >= manifest.valid_until) { this.invalidate('expired'); return fail('expired') }; if (this.leaseClock() - this.pointerCheckedAt >= 60) { this.invalidate('pointer_lease_expired'); return fail('pointer_lease_expired') }; return manifest }
  private pointer(bytes: Uint8Array): Pointer {
    const pointer = parseCanonical<Pointer>(bytes)
    if (!pointer || !exactKeys(pointer, ['format_version', 'manifest_path', 'manifest_sha256', 'release_id']) || pointer.format_version !== 3 || !/^[0-9a-f]{64}$/.test(pointer.release_id) || !/^[0-9a-f]{64}$/.test(pointer.manifest_sha256) || pointer.manifest_path !== `/_atlas/releases/${pointer.release_id}/manifest.json`) return fail('manifest')
    return pointer
  }
  private armLease(): void {
    if (this.leaseTimer) clearTimeout(this.leaseTimer)
    if (this.revalidateTimer) clearTimeout(this.revalidateTimer)
    const age = this.leaseClock() - this.pointerCheckedAt; const epoch = this.leaseEpoch
    this.leaseTimer = setTimeout(() => this.leaseDeadline(epoch), Math.max(1, (60 - age) * 1000))
    this.revalidateTimer = setTimeout(() => { void this.revalidate(epoch) }, Math.max(1, (55 - age) * 1000))
    ;(this.leaseTimer as unknown as { unref?: () => void }).unref?.()
    ;(this.revalidateTimer as unknown as { unref?: () => void }).unref?.()
  }
  private leaseDeadline(epoch: number): void { if (epoch !== this.leaseEpoch) return; if (this.leaseClock() - this.pointerCheckedAt >= 60) { this.clear(); this.invalidate('pointer_lease_expired') } else this.armLease() }
  private async revalidate(epoch: number): Promise<void> {
    const controller = new AbortController(); this.revalidateController = controller
    try {
      const requestAt = this.leaseClock()
      const pointer = this.pointer(await this.read('/_atlas/current.json', 4096, controller.signal))
      if (epoch !== this.leaseEpoch || controller.signal.aborted) return
      if (!this.manifest || this.clock() >= this.manifest.valid_until) { this.clear(); this.invalidate('expired'); return }
      if (pointer.manifest_sha256 !== this.pointerHash || pointer.release_id !== this.manifest.release_id) { this.clear(); this.invalidate('release_changed'); return }
      if (this.leaseClock() - requestAt >= 60) return
      this.pointerCheckedAt = requestAt; this.armLease()
    } catch { /* The existing hard deadline remains armed; failed fetches never renew it. */ }
    finally { if (this.revalidateController === controller) this.revalidateController = null }
  }
  private armExpiry(): void {
    if (this.expiryTimer) clearTimeout(this.expiryTimer)
    const remaining = this.current().valid_until - this.clock()
    this.expiryTimer = setTimeout(() => { try { this.current(); this.armExpiry() } catch { this.clear(); this.invalidate('expired') } }, Math.min(remaining * 1000, 86400000))
    // A Node parity-test process is allowed to exit; browsers do not have unref.
    ;(this.expiryTimer as unknown as { unref?: () => void }).unref?.()
  }
  private async read(path: string, limit: number, signal?: AbortSignal): Promise<Uint8Array> {
    checkAbort(signal)
    const response = await this.fetcher(path, { signal, cache: 'no-store', credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer' })
    if (!response.ok || !response.body || Number(response.headers.get('content-length') ?? 0) > limit) return fail('missing_object')
    const reader = response.body.getReader(); const chunks: Uint8Array[] = []; let length = 0
    try { while (true) { checkAbort(signal); const { done, value } = await reader.read(); if (done) break; length += value.length; if (length > limit) return fail('length'); chunks.push(value) } } finally { await reader.cancel(); reader.releaseLock() }
    const output = new Uint8Array(length); let offset = 0; for (const chunk of chunks) { output.set(chunk, offset); offset += chunk.length }
    return output
  }
  private async ready(signal?: AbortSignal): Promise<void> {
    if (this.manifest && this.leaseClock() - this.pointerCheckedAt < 60) { checkAbort(signal); this.current(); return }
    const requestAt = this.leaseClock()
    const pointer = this.pointer(await this.read('/_atlas/current.json', 4096, signal))
    if (this.pointerHash === pointer.manifest_sha256 && this.manifest) { this.pointerCheckedAt = requestAt; this.current(); this.armLease(); return }
    if (this.manifest) { this.clear(); this.invalidate('release_changed') }
    const bytes = await this.read(pointer.manifest_path, 4 * 1024 * 1024, signal)
    if (await hash(bytes) !== pointer.manifest_sha256) return fail('integrity')
    const manifest = parseCanonical<Manifest>(bytes)
    if (!manifest || !exactKeys(manifest, ['codec', 'format_version', 'mode', 'objects', 'release_id', 'schema_version', 'valid_from', 'valid_until']) || manifest.codec !== 'zstd-1' || manifest.format_version !== 3 || manifest.schema_version !== 3 || !['synthetic', 'production'].includes(manifest.mode) || manifest.release_id !== pointer.release_id || !Number.isSafeInteger(manifest.valid_from) || !Number.isSafeInteger(manifest.valid_until) || manifest.valid_from < 0 || manifest.valid_until <= manifest.valid_from || manifest.valid_until - manifest.valid_from > 720 * 3600 || !Array.isArray(manifest.objects) || manifest.objects.length === 0 || manifest.objects.length >= 18500) return fail('manifest')
    const { release_id: _id, ...descriptor } = manifest
    if (await hash(new TextEncoder().encode(canonical(descriptor))) !== manifest.release_id) return fail('manifest')
    let previous = ''; let routerHash = ''
    for (const object of manifest.objects) {
      if (!exactKeys(object, ['bytes', 'kind', 'partition', 'sha256']) || !/^[0-9a-f]{64}$/.test(object.sha256) || object.sha256 <= previous || !Number.isInteger(object.bytes) || object.bytes < 64 || object.bytes >= MAX_FILE || !Number.isInteger(object.kind) || object.kind < 1 || object.kind > 14 || !validPartition(object.partition)) return fail('manifest')
      previous = object.sha256; this.inventory.set(object.sha256, object)
      if (object.kind === 1) { if (routerHash || object.partition !== 'all') return fail('manifest'); routerHash = object.sha256 }
    }
    if (!routerHash) return fail('manifest')
    this.manifest = manifest; this.pointerHash = pointer.manifest_sha256; this.pointerCheckedAt = requestAt; this.current(); this.router = await this.object(routerHash, signal); this.routerBytes = this.shardBytes(this.router); this.residents.get(routerHash)!.router = true; this.armExpiry(); this.armLease()
  }
  private async object(key: string, signal?: AbortSignal): Promise<Shard> {
    this.current(); checkAbort(signal)
    const active = this.active.get(key); if (active) return active
    const cached = this.cache.get(key)
    if (cached) { this.admit(key, this.shardBytes(cached)); this.active.set(key, cached); if (this.cache.has(key)) { this.cache.delete(key); this.cache.set(key, cached) }; return cached }
    const info = this.inventory.get(key); if (!info) return fail('missing_object')
    const stored = await this.persistent.get(key, info.bytes)
    const bytes = stored ?? await this.read(`/_atlas/objects/${key}.via3`, MAX_FILE - 1, signal)
    if (bytes.length !== info.bytes || await hash(bytes) !== key) { if (stored) await this.persistent.evict(key); return fail('integrity') }
    checkAbort(signal); this.current()
    if (bytes.length < 64 || view(bytes).getBigUint64(36, true) > BigInt(PUBLIC_OBJECT)) return fail('resource_limit')
    this.admit(key, Number(view(bytes).getBigUint64(36, true)))
    const shard = await parseShard(bytes, signal)
    checkAbort(signal); this.current()
    if (shard.kind !== info.kind) return fail('schema')
    const references = shard.rows(7)
    for (let p = 0; p < references.length; p += 40) { const target = hex(references.subarray(p + 8, p + 40)); const object = this.inventory.get(target); if (!object || object.kind !== u16(references, p) || object.bytes !== u32(references, p + 4) || target === key) return fail('record') }
    if (info.partition.startsWith('4:') || info.partition.startsWith('6:')) {
      const [address, length] = info.partition.slice(2).split('/'); const partition = new Uint8Array(32); partition[0] = info.partition[0] === '4' ? 4 : 6; partition[1] = Number(length); partition.set(unhex(address!), 4)
      if (!validKey(partition)) return fail('manifest')
      const overlay = shard.rows(8)
      for (let p = 0; p < overlay.length; p += 32) { const row = overlay.subarray(p, p + 32); if (row[0] !== partition[0] || row[1]! > partition[1]!) return fail('record'); const candidate = keyFor(prefixText(partition).split('/')[0]!, row[1]!, false); if (compareKey(candidate, row) !== 0) return fail('record') }
      const local = shard.rows(1)
      for (let p = 0; p < local.length; p += 32) { const row = local.subarray(p, p + 32); if (row[0] !== partition[0] || row[1]! < partition[1]!) return fail('record'); const candidate = keyFor(prefixText(row).split('/')[0]!, partition[1]!, false); if (compareKey(candidate, partition) !== 0) return fail('record') }
    }
    if (info.partition.startsWith('asn:')) { const [, first, last] = info.partition.split(':'); const index = shard.rows(2); for (let p = 0; p < index.length; p += 8) if (u32(index, p) < Number(first) || u32(index, p) > Number(last)) return fail('record') }
    if (!stored) await this.persistent.put(key, bytes)
    checkAbort(signal); this.current()
    const size = [...shard.sections.values()].reduce((sum, bytes) => sum + bytes.length, 0)
    if (size <= 32 * 1024 * 1024) {
      while (this.cacheBytes + size > 32 * 1024 * 1024 && this.cache.size) this.evictCache(this.cache.keys().next().value!)
      this.cache.set(key, shard); this.cacheBytes += size
      this.residents.get(key)!.cache = true
    }
    this.active.set(key, shard)
    checkAbort(signal); this.current(); return shard
  }
  private async reference(shard: Shard, index: number, signal?: AbortSignal): Promise<Shard> { const objects = shard.rows(7); if (index >= objects.length / 40) return fail('record'); return this.object(hex(objects.subarray(index * 40 + 8, index * 40 + 40)), signal) }
  private async label(shard: Shard, row: Uint8Array, p: number, signal?: AbortSignal): Promise<string | null> {
    const object = u32(row, p); const id = u32(row, p + 4); if (object === NONE && id === NONE) return null
    const dictionary = await this.reference(shard, object, signal); const offsets = dictionary.rows(5); const text = dictionary.rows(6)
    if (dictionary.kind !== 14 || id + 1 >= offsets.length / 4) return fail('record')
    return textDecoder.decode(text.subarray(u32(offsets, id * 4), u32(offsets, (id + 1) * 4)))
  }
  private originList(shard: Shard, row: Uint8Array): number[] { const ints = shard.rows(4); return Array.from({ length: u32(row, 8) }, (_, index) => u32(ints, (u32(row, 4) + index) * 4)) }
  private async destinations(input: Input, signal?: AbortSignal): Promise<Map<number, Shard>> {
    const router = this.router!; const row = input.kind === 'ip' ? router.prefix(input.canonical)?.row : router.asn(Number(input.canonical.slice(2)))[0]
    const output = new Map<number, Shard>(); if (!row) return output
    const ints = router.rows(4)
    for (let index = 0; index < u16(row, 4); index++) { const shard = await this.reference(router, u32(ints, (u32(row, 0) + index) * 4), signal); output.set(shard.kind, shard) }
    return output
  }
  async lookup(q: string, signal?: AbortSignal): Promise<LookupAnswer> {
    const input = parseInput(q); this.beginQuery()
    try { return await this.lookupInput(input, signal) } finally { this.endQuery() }
  }
  private async lookupInput(input: Input, signal?: AbortSignal): Promise<LookupAnswer> {
    const budget = new AnswerBudget(); await this.ready(signal); const manifest = this.current(); const dest = await this.destinations(input, signal)
    const answer: LookupAnswer = { q: input.canonical, kind: input.kind, releaseId: manifest.release_id, synthetic: manifest.mode === 'synthetic', validUntil: manifest.valid_until, geo: null, network: null, usage: null, quality: null, asns: [], bgp: { origins: [], paths: [], relationships: [], tier1: [], rpki: [] } }
    let announcement: string | null = null
    if (input.kind === 'ip') {
      let networkOriginsKnown = false
      const geo = dest.get(2); const geoRow = geo?.prefix(input.canonical)?.row
      if (geo && geoRow) answer.geo = { country: country(u16(geoRow, 4)), registrationCountry: country(u16(geoRow, 6)), region: await this.label(geo, geoRow, 8, signal), city: await this.label(geo, geoRow, 16, signal), latitude: null, longitude: null, precision: null }
      const coords = dest.get(3)?.prefix(input.canonical)?.row
      if (coords && has(coords, 4)) { answer.geo ??= { country: null, registrationCountry: null, region: null, city: null, latitude: null, longitude: null, precision: null }; answer.geo.latitude = i32(coords, 4) / 1000; answer.geo.longitude = i32(coords, 8) / 1000; answer.geo.precision = ['unknown', 'country', 'region', 'city_centroid', 'area'][coords[12]!]! }
      const network = dest.get(4); const found = network?.prefix(input.canonical)
      if (network && found) { budget.charge(4096 + 16 * u32(found.row, 8)); answer.network = { prefix: found.prefix, name: await this.label(network, found.row, 16, signal), organization: await this.label(network, found.row, 24, signal), isp: await this.label(network, found.row, 32, signal), origins: this.originList(network, found.row) }; networkOriginsKnown = has(found.row, 19); if (networkOriginsKnown) announcement = found.prefix; answer.bgp.origins = answer.network.origins }
      const use = dest.get(5)?.prefix(input.canonical)?.row
      if (use) { answer.usage = { type: usage(use[4]!), assignment: ['unknown', 'native', 'broadcast_or_routed'][use[5]!]!, anycast: has(use, 7) ? !!(use[6]! & 1) : null, directedBroadcast: has(use, 8) ? !!(use[6]! & 2) : null }; if (answer.usage.anycast && answer.geo) { answer.geo.city = null; answer.geo.latitude = null; answer.geo.longitude = null; answer.geo.precision = null } }
      const quality = dest.get(6)?.prefix(input.canonical)?.row
      if (quality) answer.quality = { score: has(quality, 9) ? quality[9]! : null, confidence: confidence(quality[10]!), reasons: reasons(u32(quality, 4)), layers: { exact: has(quality, 10) ? u32(quality, 12) / 1e6 : null, prefix: has(quality, 11) ? u32(quality, 16) / 1e6 : null, asn: has(quality, 12) ? u32(quality, 20) / 1e6 : null, neighbors: has(quality, 13) ? u32(quality, 24) / 1e6 : null } }
      const originShard = dest.get(10); const originFound = originShard?.prefix(input.canonical); const originRow = originFound?.row
      if (originShard && originRow && has(originRow, 19)) { budget.charge(16 * u32(originRow, 8)); const values = this.originList(originShard, originRow); if (networkOriginsKnown && (answer.network!.origins.length !== values.length || values.some((value, index) => value !== answer.network!.origins[index]))) return fail('record'); answer.bgp.origins = values; announcement = originFound!.prefix }
    } else answer.bgp.origins = [Number(input.canonical.slice(2))]
    for (const asn of answer.bgp.origins) {
      const related = await this.destinations({ kind: 'asn', canonical: `AS${asn}` }, signal)
      const aggregate = related.get(8); const row = aggregate?.asn(asn)[0]
      if (aggregate && row) {
        budget.charge(4096)
        const info: ASNAnswer = { asn, name: await this.label(aggregate, row, 8, signal), organization: await this.label(aggregate, row, 16, signal), country: country(u16(row, 24)), risk: has(row, 23) ? u32(row, 28) / 1e6 : null, riskBand: ['unknown', 'low', 'medium', 'high'][row[26]!]!, confidence: confidence(row[27]!), prefixes: [], prefixCursor: null, customerCone: has(row, 25) ? u32(row, 44) : null, transitDegree: has(row, 26) ? u32(row, 48) : null, networkClass: networkClass(row[52]!), stability: stability(row[53]!) }
        if (u32(row, 40) > 0) budget.charge(64 * u32(aggregate.rows(12), u32(row, 36) * 16 + 8))
        const page = await this.prefixPage(aggregate, row, asn, 0, signal)
        info.prefixes = page.prefixes; info.prefixCursor = page.nextCursor
        answer.asns.push(info)
      }
      const paths = related.get(11)
      if (paths) {
        const rows = paths.asn(asn, true); if (rows.length > 12) return fail('record')
        const segments = paths.rows(9); const ints = paths.rows(4)
        for (const row of rows) { const path: BGPAnswer['paths'][number] = { origin: asn, asns: [], visibility: ['unknown', 'low', 'medium', 'high'][row[15]!]!, graphEligible: !!(row[14]! & 1), segments: [] }; for (let j = u32(row, 8); j < u32(row, 8) + u16(row, 12); j++) { const segment = segments.subarray(j * 12, (j + 1) * 12); budget.path(u32(segment, 8)); const asns = Array.from({ length: u32(segment, 8) }, (_, index) => u32(ints, (u32(segment, 4) + index) * 4)); path.segments.push({ type: ['', 'sequence', 'set', 'confederation_sequence', 'confederation_set'][segment[0]!]!, asns }); path.asns.push(...asns) }; answer.bgp.paths.push(path) }
      }
      const tier = related.get(13)?.asn(asn)[0]
      if (tier) answer.bgp.tier1.push({ asn, networkClass: networkClass(tier[8]!), stability: stability(tier[9]!) })
      if (input.kind === 'ip') {
        let status = 'unavailable'
        const row = dest.get(9)?.rpki(input.canonical, asn, announcement)
        if (row) status = ['unavailable', 'valid', 'invalid', 'not_found'][row[8]!]!
        answer.bgp.rpki.push({ origin: asn, status })
      }
    }
    const pairs = new Map<string, [number, number]>()
    for (const path of answer.bgp.paths) if (path.graphEligible) for (let index = 1; index < path.asns.length; index++) { const from = path.asns[index - 1]!; const to = path.asns[index]!; if (from !== to) pairs.set(`${from}:${to}`, [from, to]) }
    for (const [from, to] of [...pairs.values()].sort(([a, b], [c, d]) => a - c || b - d)) { checkAbort(signal); budget.charge(256); const related = await this.destinations({ kind: 'asn', canonical: `AS${from}` }, signal); const row = related.get(12)?.relationship(from, to); answer.bgp.relationships.push({ from, to, relation: row ? ['unknown', 'transit_upstream', 'peer', 'customer', 'sibling'][row[12]!]! : 'unknown', observed: true, inferred: !!row && !!(row[13]! & 2) }) }
    checkAbort(signal); this.current(); answerFits(answer); return answer
  }
  private async prefixPage(shard: Shard, row: Uint8Array, asn: number, cursor: number, signal?: AbortSignal): Promise<ASNPrefixPage> {
    const output: ASNPrefixPage = { asn, prefixes: [], nextCursor: null }
    const count = u32(row, 40)
    if (count === 0 && cursor === 0) return output
    if (!Number.isSafeInteger(cursor) || cursor < 0 || cursor >= count) return fail('invalid_cursor')
    const page = shard.rows(12).subarray((u32(row, 36) + cursor) * 16, (u32(row, 36) + cursor + 1) * 16)
    const target = await this.reference(shard, u32(page, 0), signal)
    if (target.kind !== 8 || target.rows(2).length || target.rows(3).length || target.rows(7).length || target.rows(12).length) return fail('record')
    const rows = target.rows(11); const first = u32(page, 4); const total = u32(page, 8)
    if (!range(first, total, rows.length / 24)) return fail('record')
    output.prefixes = Array.from({ length: total }, (_, index) => prefixText(rows.subarray((first + index) * 24, (first + index + 1) * 24)))
    output.nextCursor = cursor + 1 < count ? cursor + 1 : null
    return output
  }
  async prefixes(q: string, cursor = 0, signal?: AbortSignal): Promise<ASNPrefixPage> {
    const input = parseInput(q); if (input.kind !== 'asn') return fail('invalid_input')
    if (!Number.isSafeInteger(cursor) || cursor < 0) return fail('invalid_cursor')
    this.beginQuery()
    try { return await this.prefixesInput(input, cursor, signal) } finally { this.endQuery() }
  }
  private async prefixesInput(input: Input, cursor: number, signal?: AbortSignal): Promise<ASNPrefixPage> {
    await this.ready(signal); const dest = await this.destinations(input, signal); const asn = Number(input.canonical.slice(2)); const shard = dest.get(8); const row = shard?.asn(asn)[0]
    if (!shard || !row) { if (cursor !== 0) return fail('invalid_cursor'); return { asn, prefixes: [], nextCursor: null } }
    const answer = await this.prefixPage(shard, row, asn, cursor, signal); checkAbort(signal); this.current(); return answer
  }
  async classC(q: string, signal?: AbortSignal): Promise<ClassCAnswer | null> {
    const input = parseInput(q); this.beginQuery()
    try { return await this.classCInput(input, signal) } finally { this.endQuery() }
  }
  private async classCInput(input: Input, signal?: AbortSignal): Promise<ClassCAnswer | null> {
    const budget = new AnswerBudget(); budget.charge(256 * 512); await this.ready(signal); this.current(); if (input.kind !== 'ip' || input.canonical.includes(':')) return null
    const dest = await this.destinations(input, signal); const shard = dest.get(7); const found = shard?.prefix(input.canonical)
    if (!shard || !found) return null
    const row = found.row; const base = input.canonical.split('.').slice(0, 3).join('.')
    const answer: ClassCAnswer = { prefix: found.prefix, cells: Array.from({ length: 256 }, (_, suffix) => ({ ip: `${base}.${suffix}`, observed: false, score: null, confidence: 'unrated', reasons: [], usage: 'unknown', origins: [] })), observedCount: u16(row, 8), assessedCount: u16(row, 10), positiveCount: u16(row, 12), aggregateScore: has(row, 22) ? row[20]! : null }
    const cells = shard.rows(10)
    for (let index = u32(row, 4); index < u32(row, 4) + u16(row, 8); index++) { const cell = cells.subarray(index * 32, (index + 1) * 32); const target = answer.cells[cell[0]!]!; target.observed = true; target.confidence = confidence(cell[9]!); target.reasons = reasons(u32(cell, 4)); target.usage = usage(cell[2]!); target.score = cell[1]! & 8 ? cell[8]! : null; if (cell[1]! & 32) { const network = await this.reference(shard, u32(cell, 16), signal); const row = network.record(u32(cell, 20)); budget.cellOrigins(u32(row, 8)); target.origins = this.originList(network, row) } }
    checkAbort(signal); this.current(); answerFits(answer); return answer
  }
}

// One queue bounds simultaneous input/frame/output work. Cancellation bypasses it.
if (typeof self !== 'undefined' && typeof window === 'undefined') {
  const reader = new AtlasReader(fetch, () => Math.floor(Date.now() / 1000), reason => self.postMessage({ event: 'invalidate', reason }))
  const controllers = new Map<number, AbortController>()
  let queue = Promise.resolve()
  self.addEventListener('message', (event: MessageEvent) => {
    const { action, id, q, cursor } = event.data
    if (action === 'cancel') { controllers.get(id)?.abort(); return }
    if (action === 'clear') { for (const controller of controllers.values()) controller.abort(); reader.clear(); return }
    if (!Number.isSafeInteger(id) || typeof q !== 'string' || !['lookup', 'classC', 'prefixes'].includes(action)) return
    if (new TextEncoder().encode(q).byteLength > 128) { self.postMessage({ id, error: 'invalid_input' }); return }
    if (controllers.size >= 8) { self.postMessage({ id, error: 'resource_limit' }); return }
    const controller = new AbortController(); controllers.set(id, controller)
    queue = queue.then(async () => {
      try { checkAbort(controller.signal); const answer = action === 'lookup' ? await reader.lookup(q, controller.signal) : action === 'prefixes' ? await reader.prefixes(q, cursor, controller.signal) : await reader.classC(q, controller.signal); checkAbort(controller.signal); answerFits(answer); self.postMessage({ id, answer }) }
      catch (error) { self.postMessage({ id, error: error instanceof Error ? error.message : 'internal' }) }
      finally { controllers.delete(id) }
    })
  })
}
