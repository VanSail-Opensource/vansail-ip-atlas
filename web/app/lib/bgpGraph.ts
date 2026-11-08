/** Ranked origin-outward observations. Projection never modifies these records. */
export type GraphPath = {
  origin: number
  asns: readonly number[]
  graphEligible: boolean
  visibility: string
  segments?: readonly { type: string; asns: readonly number[] }[]
}
export type GraphRelation = { from: number; to: number; relation: string; observed: boolean; inferred: boolean }
export type GraphNode = { asn: number; depth: number; x: number; y: number }
export type ProjectedRoute = {
  pathIndex: number
  original: GraphPath
  asns: number[]
  originalPositions: number[]
  truncated: boolean
}
export type ProjectedEdge = {
  key: string
  from: number
  to: number
  fromOriginalPosition: number
  toOriginalPosition: number
  routeIds: number[]
  relation: string
  observed: true
  inferred: boolean
}

const MAX_NODES = 24
const PROTECTED_NODES = 3 // The origin is hop zero, followed by two protected hops.
const MAX_EXITS = 3
const relationships = new Set(['transit_upstream', 'peer', 'customer', 'sibling'])
const validASN = (asn: number) => Number.isInteger(asn) && asn > 0 && asn <= 0xffffffff

/** Build once from ranked observations; route focus is deliberately not an input. */
export function projectGraph(paths: readonly GraphPath[], relations: readonly GraphRelation[], origin: number) {
  const normalized: { pathIndex: number; original: GraphPath; asns: number[]; first: number[]; last: number[] }[] = []
  const protectedNodes = new Set<number>()
  const omittedPathIndexes: number[] = []
  for (const [pathIndex, original] of paths.entries()) {
    if (original.origin !== origin || !original.graphEligible || !validASN(origin) ||
        original.segments?.some(segment => segment.type !== 'sequence')) continue
    const asns: number[] = [], first: number[] = [], last: number[] = []
    const seen = new Set<number>()
    let valid = original.asns.length > 0 && original.asns[0] === origin
    for (const [position, asn] of original.asns.entries()) {
      if (!validASN(asn)) { valid = false; break }
      if (asn === asns.at(-1)) { last[last.length - 1] = position; continue }
      if (seen.has(asn)) { valid = false; break }
      seen.add(asn); asns.push(asn); first.push(position); last.push(position)
    }
    if (!valid) continue // A loop or nonlinear observation cannot become a simple path.
    const protectedPrefix = asns.slice(0, PROTECTED_NODES)
    const additional = protectedPrefix.filter(asn => !protectedNodes.has(asn)).length
    if (protectedNodes.size + additional > MAX_NODES) { omittedPathIndexes.push(pathIndex); continue }
    for (const asn of protectedPrefix) protectedNodes.add(asn)
    normalized.push({ pathIndex, original, asns, first, last })
  }

  const supportedRelations = new Map<string, { relation: string; inferred: boolean } | null>()
  for (const row of relations) {
    const key = `${row.from}:${row.to}`
    const value = { relation: row.inferred && relationships.has(row.relation) ? row.relation : 'unknown',
      inferred: row.inferred && relationships.has(row.relation) }
    if (!supportedRelations.has(key)) supportedRelations.set(key, value)
    else {
      const previous = supportedRelations.get(key)
      if (previous?.relation !== value.relation || previous?.inferred !== value.inferred) supportedRelations.set(key, null)
    }
  }

  // Reserve every selected protection set before letting a long route fill suffix slots.
  const nodes = new Map<number, GraphNode>()
  const addNode = (asn: number, depth: number) => {
    const previous = nodes.get(asn)
    if (!previous) nodes.set(asn, { asn, depth, x: 0, y: 0 })
    else previous.depth = Math.min(previous.depth, depth)
  }
  for (const route of normalized) route.asns.slice(0, PROTECTED_NODES).forEach(addNode)
  const exits = new Map<number, Set<number>>()
  const routes: ProjectedRoute[] = []
  const edges = new Map<string, ProjectedEdge>()
  const terminals = new Set<number>()
  for (const route of normalized) {
    let visible = Math.min(PROTECTED_NODES, route.asns.length)
    for (let depth = PROTECTED_NODES; depth < route.asns.length; depth++) {
      const asn = route.asns[depth]!
      if (!nodes.has(asn) && nodes.size >= MAX_NODES) break
      if (depth === PROTECTED_NODES) {
        const second = route.asns[2]!
        const allowed = exits.get(second) ?? new Set<number>()
        if (!allowed.has(asn) && allowed.size >= MAX_EXITS) break
        allowed.add(asn); exits.set(second, allowed)
      }
      addNode(asn, depth); visible++
    }
    const truncated = visible < route.asns.length
    const selected: ProjectedRoute = { pathIndex: route.pathIndex, original: route.original,
      asns: route.asns.slice(0, visible), originalPositions: route.first.slice(0, visible), truncated }
    const routeId = routes.length
    routes.push(selected)
    if (truncated) terminals.add(selected.asns.at(-1)!)
    for (let depth = 1; depth < visible; depth++) {
      const from = selected.asns[depth - 1]!, to = selected.asns[depth]!
      // These are neighboring original positions, even when display prepends collapse.
      const fromOriginalPosition = route.last[depth - 1]!, toOriginalPosition = route.first[depth]!
      const key = `${from}:${to}:${fromOriginalPosition}:${toOriginalPosition}`
      const previous = edges.get(key)
      if (previous) { previous.routeIds.push(routeId); continue }
      const relation = supportedRelations.get(`${from}:${to}`)
      edges.set(key, { key, from, to, fromOriginalPosition, toOriginalPosition, routeIds: [routeId],
        relation: relation?.relation ?? 'unknown', inferred: relation?.inferred ?? false, observed: true })
    }
  }

  const levels = new Map<number, number[]>()
  for (const node of nodes.values()) {
    const level = levels.get(node.depth) ?? []
    level.push(node.asn); levels.set(node.depth, level)
  }
  const maxDepth = Math.max(1, ...levels.keys())
  for (const [depth, asns] of levels) {
    asns.sort((a, b) => a - b)
    asns.forEach((asn, index) => Object.assign(nodes.get(asn)!, { x: 70 + depth * (660 / maxDepth), y: (index + 1) * 380 / (asns.length + 1) }))
  }
  return { nodes: [...nodes.values()].sort((a, b) => a.asn - b.asn), byId: nodes, routes,
    edges: [...edges.values()].sort((a, b) => a.from - b.from || a.to - b.to || a.fromOriginalPosition - b.fromOriginalPosition || a.toOriginalPosition - b.toOriginalPosition),
    omittedPathIndexes, truncatedTerminals: [...terminals].sort((a, b) => a - b),
    truncated: omittedPathIndexes.length > 0 || routes.some(route => route.truncated) }
}
