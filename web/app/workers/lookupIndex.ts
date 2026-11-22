export type ObjectInfo = { bytes: number; kind: number; partition: string; sha256: string }
export type Snapshot = { mode: 'production' | 'synthetic'; release_id: string; valid_from: number; valid_until: number }
type Plane = 'ipv4' | 'ipv6' | 'asn' | 'objects'
type Root = Snapshot & { format_version: number; manifest_sha256: string; roots: Record<Plane, string> }
type Branch = { type: 'branch'; children: [number, string][] }
type Objects = { type: 'objects'; objects: ObjectInfo[] }
type Routes = { type: 'routes'; objects: ObjectInfo[]; sets: number[][]; routes: [string, string, number][] }
type Node = Branch | Routes | Objects
type FetchControl = (digest: string, limit: number, signal?: AbortSignal) => Promise<unknown>

const bad = (): never => { throw new Error('manifest') }
export const digest = (value: unknown): value is string => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value)
const keys = (value: unknown, names: string[]): boolean =>
  !!value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === names.length && names.every(name => Object.hasOwn(value, name))
const integer = (value: unknown, max: number): value is number =>
  typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value < max

export function readRoot(value: unknown, release: string, manifest: string): Root {
  if (!keys(value, ['format_version','manifest_sha256','mode','release_id','roots','valid_from','valid_until'])) return bad()
  const root = value as Root
  if (root.format_version !== 1 || root.manifest_sha256 !== manifest || root.release_id !== release ||
      !['production','synthetic'].includes(root.mode) || !keys(root.roots, ['ipv4','ipv6','asn','objects']) || !Object.values(root.roots).every(digest) ||
      !Number.isSafeInteger(root.valid_from) || !Number.isSafeInteger(root.valid_until) || root.valid_from < 0 ||
      root.valid_until <= root.valid_from || root.valid_until - root.valid_from > 720 * 3600) return bad()
  return root
}

export class LookupIndex {
  private cache = new Map<string, Node>()
  private readonly root: Root
  private readonly read: FetchControl
  private readonly validInfo: (info: ObjectInfo) => boolean
  constructor(root: Root, read: FetchControl, validInfo: (info: ObjectInfo) => boolean) {
    this.root = root
    this.read = read
    this.validInfo = validInfo
  }

  private async node(hash: string, plane: Plane, prefix: string, width: number, signal?: AbortSignal): Promise<Node> {
    // Bind cached validation to the plane and prefix as well as the content.
    const cacheKey = plane + '/' + prefix + '/' + hash
    const cached = this.cache.get(cacheKey)
    if (cached) return cached
    const limit = plane === 'objects' ? 2048 : 4096
    const node = await this.read(hash, limit, signal) as Node
    if (!node || typeof node !== 'object') return bad()
    if (node.type === 'branch') {
      if (!keys(node, ['type','children']) || prefix.length >= width || !Array.isArray(node.children) || !node.children.length || node.children.length > 16) return bad()
      let previous = -1
      for (const row of node.children) {
        if (!Array.isArray(row) || row.length !== 2 || !integer(row[0],16) || row[0] <= previous || !digest(row[1])) return bad()
        previous = row[0]
      }
    } else {
      if (plane === 'objects' ? node.type !== 'objects' || !keys(node,['type','objects']) : node.type !== 'routes' || !keys(node,['type','objects','routes','sets'])) return bad()
      if (!Array.isArray(node.objects) || !node.objects.every(o => this.validInfo(o))) return bad()
      if (node.type === 'objects') {
        if (!node.objects.every((o,i) => o.sha256.startsWith(prefix) && (!i || node.objects[i-1]!.sha256 < o.sha256))) return bad()
      } else {
        if (!Array.isArray(node.sets) || !Array.isArray(node.routes)) return bad()
        for (const set of node.sets) {
          if (!Array.isArray(set) || set.length > 12) return bad()
          let previousKind = 1
          for (const ordinal of set) {
            if (!integer(ordinal,node.objects.length)) return bad()
            const kind = node.objects[ordinal]!.kind
            if (kind <= previousKind || kind > 13) return bad()
            previousKind = kind
          }
        }
        let previous = ''
        for (const row of node.routes) {
          if (!Array.isArray(row) || row.length !== 3 || !integer(row[2],node.sets.length)) return bad()
          const [first,last] = row
          if (![first,last].every(s => typeof s === 'string' && s.length === width && s.startsWith(prefix) && /^[0-9a-f]+$/.test(s)) ||
              first <= previous || last < first) return bad()
          previous = last
        }
      }
    }
    // Two hundred and fifty-six bounded pages allow reuse across ASN hops and
    // successive owner views without retaining the entire control directory.
    if (this.cache.size >= 256) this.cache.delete(this.cache.keys().next().value!)
    this.cache.set(cacheKey, node)
    return node
  }

  private async leaf(plane: Plane, key: string, signal?: AbortSignal): Promise<Objects | Routes | undefined> {
    let hash = this.root.roots[plane]
    for (let depth = 0; depth <= key.length; depth++) {
      const page = await this.node(hash, plane, key.slice(0,depth), key.length, signal)
      if (page.type !== 'branch') return page
      const child = page.children.find(([digit]) => digit === parseInt(key[depth]!,16))
      if (!child) return
      hash = child[1]
    }
    return bad()
  }

  async routes(plane: Exclude<Plane,'objects'>, key: string, signal?: AbortSignal): Promise<ObjectInfo[]> {
    const leaf = await this.leaf(plane, key, signal)
    if (!leaf) return []
    if (leaf.type !== 'routes') return bad()
    let lo = 0, hi = leaf.routes.length
    while (lo < hi) {
      const mid = (lo + hi) >>> 1
      if (leaf.routes[mid]![1] < key) lo = mid + 1
      else hi = mid
    }
    const row = leaf.routes[lo]
    return row && row[0] <= key ? leaf.sets[row[2]]!.map(index => leaf.objects[index]!) : []
  }

  async object(key: string, signal?: AbortSignal): Promise<ObjectInfo | undefined> {
    const leaf = await this.leaf('objects', key, signal)
    if (!leaf) return
    if (leaf.type !== 'objects') return bad()
    return leaf.objects.find(info => info.sha256 === key)
  }
}
