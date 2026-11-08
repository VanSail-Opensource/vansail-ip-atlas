import assert from 'node:assert/strict'
import { test } from 'node:test'
import { readFileSync } from 'node:fs'
import { projectGraph } from '../app/lib/bgpGraph.ts'
import { AtlasReader } from '../app/workers/atlas.ts'

const path = (asns: number[], graphEligible = true) => ({ origin: asns[0]!, asns, graphEligible, visibility: 'high' })
const relation = (from: number, to: number, value: string) => ({ from, to, relation: value, observed: true, inferred: value !== 'unknown' })
const sequence = (start: number, count: number) => Array.from({ length: count }, (_, index) => start + index)

test('a long observed route keeps its protected hops and a disclosed contiguous prefix', () => {
  const original = Object.freeze({ ...path(sequence(100, 40)), asns: Object.freeze(sequence(100, 40)) })
  const before = JSON.stringify(original)
  const graph = projectGraph([original], [], 100)
  assert.equal(graph.nodes.length, 24)
  assert.deepEqual(graph.routes[0]!.asns, sequence(100, 24))
  assert.equal(graph.routes[0]!.original, original)
  assert.deepEqual(graph.routes[0]!.originalPositions, sequence(0, 24))
  assert.equal(graph.routes[0]!.truncated, true)
  assert.equal(graph.truncated, true)
  assert.deepEqual(graph.truncatedTerminals, [123])
  assert.equal(graph.edges.length, 23)
  assert.equal(JSON.stringify(original), before)
})

test('every admitted route reserves its complete first two hops before filling long suffixes', () => {
  const graph = projectGraph([path(sequence(100, 40)), path([100, 800, 900, 901])], [], 100)
  assert.equal(graph.nodes.length, 24)
  assert.deepEqual(graph.routes[1]!.asns, [100, 800, 900])
  for (const asn of [100, 101, 102, 800, 900]) assert(graph.byId.has(asn))
  assert.equal(graph.routes[1]!.truncated, true)
})

test('a fourth distinct second-hop exit clips the suffix without losing protected nodes', () => {
  const graph = projectGraph([400, 401, 402, 403].map(exit => path([100, 200, 300, exit])), [], 100)
  assert.equal(graph.routes.length, 4)
  assert.deepEqual(graph.routes[3]!.asns, [100, 200, 300])
  assert.deepEqual(graph.edges.filter(edge => edge.from === 300).map(edge => edge.to), [400, 401, 402])
  assert.equal(graph.routes[3]!.original.asns[3], 403)
  assert.equal(graph.routes[3]!.truncated, true)
  assert(graph.truncatedTerminals.includes(300))
})

test('a missing intermediate hop never reconnects to an existing distant node', () => {
  const graph = projectGraph([path(sequence(100, 40)), path([100, 800, 900, 901, 105])], [], 100)
  assert(graph.byId.has(105))
  assert.deepEqual(graph.routes[1]!.asns, [100, 800, 900])
  assert(!graph.edges.some(edge => edge.from === 900 && edge.to === 105))
  assert(!graph.edges.some(edge => edge.routeIds.includes(1) && edge.to === 105))
})

test('prepends collapse only for display and edge endpoints retain actual original positions', () => {
  const original = path([100, 100, 200, 200, 300, 400])
  const graph = projectGraph([original], [], 100)
  assert.deepEqual(graph.routes[0]!.asns, [100, 200, 300, 400])
  assert.deepEqual(graph.routes[0]!.originalPositions, [0, 2, 4, 5])
  assert.deepEqual(graph.edges.map(edge => [edge.from, edge.to, edge.fromOriginalPosition, edge.toOriginalPosition]),
    [[100, 200, 1, 2], [200, 300, 3, 4], [300, 400, 4, 5]])
  assert.deepEqual(original.asns, [100, 100, 200, 200, 300, 400])
})

test('nonlinear, looping, reversed or unrelated-origin inputs do not become simple observed paths', () => {
  const graph = projectGraph([path([100, 200, 300], false), path([100, 200, 100]),
    { ...path([200, 100]), origin: 100 }, path([200, 300]),
    { ...path([100, 200]), segments: [{ type: 'set', asns: [100, 200] }] }], [], 100)
  assert.equal(graph.nodes.length, 0)
  assert.equal(graph.edges.length, 0)
})

test('missing, reversed and conflicting relationship rows stay unknown, while supported peer is explicit', () => {
  const graph = projectGraph([path([100, 200, 300, 400])], [
    relation(200, 100, 'transit_upstream'), relation(100, 300, 'peer'),
    relation(200, 300, 'peer'), relation(300, 400, 'customer'), relation(300, 400, 'peer'),
  ], 100)
  assert.deepEqual(graph.edges.map(edge => [edge.from, edge.to, edge.relation, edge.observed, edge.inferred]), [
    [100, 200, 'unknown', true, false], [200, 300, 'peer', true, true], [300, 400, 'unknown', true, false],
  ])
})

test('shared trunks merge only identical actual endpoint positions, never different prepend gaps', () => {
  const graph = projectGraph([path([100, 200, 300]), path([100, 100, 200, 300]), path([100, 200, 300])], [], 100)
  const first = graph.edges.filter(edge => edge.from === 100 && edge.to === 200)
  assert.equal(first.length, 2)
  assert.deepEqual(first[0]!.routeIds, [0, 2])
  assert.deepEqual(first[1]!.routeIds, [1])
  assert.notEqual(first[0]!.key, first[1]!.key)
  for (const edge of graph.edges) for (const routeId of edge.routeIds) {
    const raw = graph.routes[routeId]!.original.asns
    assert.equal(raw[edge.fromOriginalPosition], edge.from)
    assert.equal(raw[edge.toOriginalPosition], edge.to)
    assert.equal(edge.toOriginalPosition, edge.fromOriginalPosition + 1)
  }
})

test('protected-set overflow omits a whole route and exposes the omission', () => {
  const input = Array.from({ length: 12 }, (_, index) => path([100, 200 + index, 300 + index]))
  const graph = projectGraph(input, [], 100)
  assert.equal(graph.nodes.length, 23)
  assert.equal(graph.routes.length, 11)
  assert.deepEqual(graph.omittedPathIndexes, [11])
  assert.equal(graph.truncated, true)
})

test('projection layout and raw paths are independent of route-focus UI state', () => {
  const inputs = [path([100, 200, 300]), path([100, 400, 500])]
  const graph = projectGraph(inputs, [], 100)
  const before = JSON.stringify(graph.nodes)
  for (const active of [-1, 0, 1, 0]) {
    const emphasized = graph.nodes.filter(node => active === -1 || graph.routes[active]!.asns.includes(node.asn))
    assert(emphasized.length >= 3)
    assert.equal(JSON.stringify(graph.nodes), before)
  }
  assert.deepEqual(inputs.map(value => value.asns), [[100, 200, 300], [100, 400, 500]])
})

test('Go-produced synthetic graph24 release has twelve complete routes and exactly24 observed nodes', async () => {
  const fixture = JSON.parse(readFileSync(new URL('../../fixtures/bin/synthetic-graph24-via3.json', import.meta.url), 'utf8'))
  const stable = (value: any): string => value === null || typeof value !== 'object' ? JSON.stringify(value) : Array.isArray(value)
    ? `[${value.map(stable).join(',')}]` : `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${stable(value[key])}`).join(',')}}`
  const files = new Map<string, Uint8Array>(fixture.objects.map((object: any) =>
    [`/_atlas/objects/${object.info.sha256}.via3`, new Uint8Array(Buffer.from(object.base64, 'base64'))]))
  files.set('/_atlas/current.json', new TextEncoder().encode(stable(fixture.pointer)))
  files.set(fixture.pointer.manifest_path, new TextEncoder().encode(stable(fixture.manifest)))
  const reader = new AtlasReader(async input => {
    const bytes = files.get(input)
    return new Response(bytes, { status: bytes ? 200 : 404, headers: { 'content-length': String(bytes?.length ?? 0) } })
  }, () => fixture.clock)
  try {
    const answer = await reader.lookup('AS424240')
    assert.deepEqual(answer, fixture.vectors.find((vector: any) => vector.q === 'AS424240').answer)
    assert.equal(answer.synthetic, true)
    const graph = projectGraph(answer.bgp.paths, answer.bgp.relationships, 424240)
    assert.equal(graph.nodes.length, 24)
    assert.equal(graph.edges.length, 23)
    assert.equal(graph.routes.length, 12)
    assert.equal(graph.truncated, false)
    for (const edge of graph.edges) for (const routeId of edge.routeIds) {
      const route = graph.routes[routeId]!.original.asns
      assert.equal(route[edge.fromOriginalPosition], edge.from)
      assert.equal(route[edge.toOriginalPosition], edge.to)
      assert.equal(edge.toOriginalPosition, edge.fromOriginalPosition + 1)
      assert.equal(edge.relation, 'unknown')
    }
  } finally { reader.clear() }
})
