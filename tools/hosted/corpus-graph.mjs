// Private streaming corpus selection. Reuse the production projection rather
// than assuming that 24 ASNs in a raw route set means 24 visible graph nodes.
import { createInterface } from 'node:readline'
import { projectGraph } from '../../web/app/lib/bgpGraph.ts'
for await (const line of createInterface({ input: process.stdin, crlfDelay: Infinity })) {
  if (Buffer.byteLength(line) > 8 * 1024 * 1024) throw new Error('corpus answer limit')
  const answer = JSON.parse(line)
  if (!/^AS[1-9][0-9]*$/.test(answer.q)) throw new Error('corpus ASN required')
  const graph = projectGraph(answer.bgp.paths, answer.bgp.relationships, Number(answer.q.slice(2)))
  process.stdout.write(JSON.stringify({ nodes: graph.nodes.length, routes: graph.routes.length }) + '\n')
}
