<script setup lang="ts">
import { projectGraph } from '~/lib/bgpGraph'
import type { GraphPath, GraphRelation, ProjectedEdge } from '~/lib/bgpGraph'
import { fitGraphLabel, graphIdentityName, graphRelationshipLegend, type GraphIdentity, type GraphNodeName } from '~/lib/bgpGraphPresentation'
const props = defineProps<{ paths: GraphPath[]; relationships: GraphRelation[]; origin: number; identities: readonly GraphIdentity[];
  loadNames: (asns: readonly number[], signal: AbortSignal) => Promise<readonly GraphNodeName[]> }>()
const scale = ref(1), x = ref(0), y = ref(0), activePath = ref(-1)
const originalOpen = ref(false)
const svg = ref<SVGSVGElement>()
const viewport = ref<HTMLDivElement>()
const fitted = ref(false)
const pointers = new Map<number, { x: number; y: number }>()
let previous: { x: number; y: number; distance: number } | undefined
const projection = computed(() => projectGraph(props.paths, props.relationships, props.origin))
const identityNames = computed(() => new Map(props.identities.map(identity => [identity.asn, graphIdentityName(identity)])))
const supplementalNames = shallowRef(new Map<number, string>())
const neededNames = computed(() => projection.value.nodes.map(node => node.asn)
  .filter(asn => asn !== props.origin && !identityNames.value.has(asn)))
watchPostEffect(onCleanup => {
  const asns = neededNames.value
  supplementalNames.value = new Map()
  if (!asns.length) return
  const controller = new AbortController()
  onCleanup(() => controller.abort())
  void props.loadNames(asns, controller.signal).then(names => {
    if (!controller.signal.aborted) supplementalNames.value = new Map(names.map(row => [row.asn, row.label]))
  }).catch(() => { /* Fallback to ASN IDs when optional labels are unavailable. */ })
})
const nodeName = (asn: number) => identityNames.value.get(asn) || supplementalNames.value.get(asn)
const nodeLabel = (asn: number) => nodeName(asn) || `AS${asn}`
const nodeTitle = (asn: number) => {
  const name = nodeName(asn)
  return `${name ? `${name} · ` : ''}AS${asn}${projection.value.truncatedTerminals.includes(asn) ? ' · a route suffix is clipped here' : ''}`
}
const focusedASNs = computed(() => activePath.value === -1 ? null : new Set(projection.value.routes[activePath.value]?.asns))
const nodeDimmed = (asn: number) => focusedASNs.value !== null && !focusedASNs.value.has(asn)
const edgeDimmed = (edge: ProjectedEdge) => activePath.value !== -1 && !edge.routeIds.includes(activePath.value)
const contentTransform = computed(() => {
  const { width, height } = projection.value.bounds
  return `translate(${x.value} ${y.value}) translate(${width / 2} ${height / 2}) scale(${scale.value}) translate(${-width / 2} ${-height / 2})`
})
const originalPaths = computed(() => props.paths.filter(path => path.origin === props.origin))
const originalNumber = (path: GraphPath) => originalPaths.value.indexOf(path) + 1
function toggleOriginal(event: Event) { originalOpen.value = (event.target as HTMLDetailsElement).open }
function originalText(path: GraphPath) {
  const names = (asns: readonly number[]) => asns.map(asn => `AS${asn}`).join(' ')
  if (!path.segments?.length) return names(path.asns)
  return path.segments.map(segment => `${segment.type.replaceAll('_', ' ')} [${names(segment.asns)}]`).join(' | ')
}
function resetView(complete: boolean) {
  scale.value = 1; x.value = 0; y.value = 0; fitted.value = complete
  if (viewport.value) { viewport.value.scrollLeft = 0; viewport.value.scrollTop = 0 }
}
function fit() { resetView(true) }
function exportGraph() {
  if (!svg.value) return
  const namespace = 'http://www.w3.org/2000/svg'
  const snapshot = svg.value.cloneNode(true) as SVGSVGElement
  // Presentation values are resolved while the themed, focused SVG is mounted.
  // Never copy arbitrary stylesheets, resource references or event handlers.
  const paint = ['fill', 'fill-opacity', 'stroke', 'stroke-opacity', 'stroke-width', 'stroke-dasharray',
    'stroke-linecap', 'stroke-linejoin', 'opacity', 'font-family', 'font-size', 'font-weight',
    'text-anchor', 'dominant-baseline', 'paint-order', 'vector-effect']
  const originals = [svg.value, ...svg.value.querySelectorAll('*')]
  const copies = [snapshot, ...snapshot.querySelectorAll('*')]
  originals.forEach((element, index) => {
    const copy = copies[index]!
    for (const attribute of [...copy.attributes]) if (attribute.name.startsWith('data-v-')) copy.removeAttribute(attribute.name)
    if (element.localName === 'title' || element.localName === 'desc') return
    const style = getComputedStyle(element)
    for (const property of paint) {
      const value = style.getPropertyValue(property).trim()
      if (value && !/url\s*\(/i.test(value)) copy.setAttribute(property, value)
    }
  })
  // HTML labels have an opaque backing in the interactive SVG so their
  // contrast does not depend on crossing edges or the page decoration.
  // The download remains self-contained native SVG, with the same paint.
  const measure = document.createElement('canvas').getContext('2d')
  const liveLabels = [...svg.value.querySelectorAll('foreignObject')]
  for (const [index, label] of [...snapshot.querySelectorAll('foreignObject')].entries()) {
    const live = liveLabels[index]!.firstElementChild!
    const style = getComputedStyle(live)
    const width = parseFloat(style.width), height = parseFloat(style.height)
    const left = Number(label.getAttribute('x')) + (Number(label.getAttribute('width')) - width) / 2
    const top = Number(label.getAttribute('y'))
    const backing = document.createElementNS(namespace, 'rect')
    for (const [name, value] of Object.entries({ x: left, y: top, width, height })) backing.setAttribute(name, String(value))
    backing.setAttribute('fill', style.backgroundColor)
    const text = document.createElementNS(namespace, 'text')
    text.setAttribute('x', String(left + width / 2)); text.setAttribute('y', String(top + 14))
    text.setAttribute('text-anchor', 'middle'); text.setAttribute('fill', style.color)
    text.setAttribute('font-family', style.fontFamily); text.setAttribute('font-size', style.fontSize)
    text.setAttribute('font-weight', style.fontWeight); text.setAttribute('direction', style.direction)
    const value = live.textContent ?? ''
    if (measure && live.classList.contains('graph-node-label')) {
      measure.font = `${style.fontWeight} ${style.fontSize} ${style.fontFamily}`
      measure.direction = style.direction === 'rtl' ? 'rtl' : 'ltr'
      text.textContent = fitGraphLabel(value, width - parseFloat(style.paddingLeft) - parseFloat(style.paddingRight),
        label => measure.measureText(label).width)
    } else text.textContent = value
    label.replaceWith(backing, text)
  }
  const { width, height } = projection.value.bounds
  snapshot.setAttribute('xmlns', namespace)
  snapshot.setAttribute('width', String(width)); snapshot.setAttribute('height', String(height))
  snapshot.removeAttribute('style')
  // Export the complete readable world, even after interactive pan or zoom.
  snapshot.querySelector('g')?.removeAttribute('transform')
  snapshot.removeAttribute('tabindex')
  snapshot.setAttribute('aria-labelledby', 'atlas-graph-title atlas-graph-description')
  const title = document.createElementNS(namespace, 'title')
  title.id = 'atlas-graph-title'; title.textContent = `AS${props.origin} observed AS paths`
  const description = document.createElementNS(namespace, 'desc')
  description.id = 'atlas-graph-description'
  description.textContent = `Observed origin-outward adjacencies. Known relationships are inferred: solid upstream, dashed peer, long-short customer and short-short sibling. Dotted means the relationship is unknown. ${projection.value.nodes.length} visible nodes. ${projection.value.truncated ? 'The bounded projection clips some routes or suffixes; dashed terminal nodes mark clipped suffixes.' : 'The selected linear routes fit within the bounded projection.'} Original segments and prepends are retained in the interactive view.`
  const background = document.createElementNS(namespace, 'rect')
  background.setAttribute('width', String(width)); background.setAttribute('height', String(height))
  background.setAttribute('fill', getComputedStyle(document.body).backgroundColor)
  snapshot.prepend(background); snapshot.prepend(description); snapshot.prepend(title)
  const url = URL.createObjectURL(new Blob([new XMLSerializer().serializeToString(snapshot)], { type: 'image/svg+xml' }))
  const link = document.createElement('a')
  link.href = url; link.download = `AS${props.origin}-observed-paths.svg`
  document.body.appendChild(link); link.click(); link.remove()
  setTimeout(() => URL.revokeObjectURL(url), 0)
}
function worldPoint(point: { x: number; y: number }) {
  const matrix = svg.value?.getScreenCTM()?.inverse()
  return matrix ? { x: matrix.a * point.x + matrix.c * point.y + matrix.e,
    y: matrix.b * point.x + matrix.d * point.y + matrix.f } : undefined
}
function zoom(value: number, anchor?: { x: number; y: number }) {
  const next = Math.min(4, Math.max(.5, value))
  const { width, height } = projection.value.bounds
  const rect = viewport.value?.getBoundingClientRect()
  anchor ??= rect ? worldPoint({ x: rect.left + rect.width / 2, y: rect.top + rect.height / 2 }) : undefined
  anchor ??= { x: width / 2, y: height / 2 }
  const ratio = next / scale.value
  x.value = anchor.x - width / 2 - (anchor.x - width / 2 - x.value) * ratio
  y.value = anchor.y - height / 2 - (anchor.y - height / 2 - y.value) * ratio
  scale.value = next
}
function wheel(event: WheelEvent) { event.preventDefault(); zoom(scale.value * Math.exp(-event.deltaY * .001), worldPoint({ x: event.clientX, y: event.clientY })) }
function center() {
  const values = [...pointers.values()]
  if (!values.length) return undefined
  return { x: values.reduce((sum, p) => sum + p.x, 0) / values.length, y: values.reduce((sum, p) => sum + p.y, 0) / values.length, distance: values.length === 2 ? Math.hypot(values[0]!.x - values[1]!.x, values[0]!.y - values[1]!.y) : 0 }
}
function down(event: PointerEvent) { svg.value?.setPointerCapture(event.pointerId); pointers.set(event.pointerId, { x: event.clientX, y: event.clientY }); previous = center() }
function move(event: PointerEvent) {
  if (!pointers.has(event.pointerId)) return
  pointers.set(event.pointerId, { x: event.clientX, y: event.clientY })
  const next = center()
  if (previous && next) {
    const from = worldPoint(previous), to = worldPoint(next)
    if (from && to) {
      x.value += to.x - from.x; y.value += to.y - from.y
      if (next.distance && previous.distance) zoom(scale.value * next.distance / previous.distance, to)
    }
  }
  previous = next
}
function up(event: PointerEvent) { pointers.delete(event.pointerId); previous = center() }
function key(event: KeyboardEvent) {
  const change: Record<string, [number, number]> = { ArrowUp: [0, 24], ArrowDown: [0, -24], ArrowLeft: [24, 0], ArrowRight: [-24, 0] }
  if (change[event.key]) { event.preventDefault(); x.value += change[event.key]![0]; y.value += change[event.key]![1] }
  else if (event.key === 'Home' || event.key === '0') { event.preventDefault(); fit() }
  else if (event.key === '+' || event.key === '=') zoom(scale.value * 1.2)
  else if (event.key === '-') zoom(scale.value / 1.2)
}
watch(() => props.origin, () => { activePath.value = -1; originalOpen.value = false; resetView(false) })
</script>

<template>
  <div class="glass bgp-graph">
    <span class="edge-accent" aria-hidden="true" />
    <div class="graph-toolbar"><label>Route <select v-model="activePath" aria-label="Focus observed route"><option :value="-1">All selected routes</option><option v-for="(path, index) in projection.routes" :key="path.pathIndex" :value="index">Route {{ originalNumber(path.original) }}{{ path.truncated ? ' · clipped' : '' }}</option></select></label><div class="graph-actions"><button class="plain-button" @click="exportGraph">Export</button><button v-if="fitted" class="plain-button" @click="resetView(false)">Actual size</button><button class="plain-button" @click="fit">Fit</button></div></div>
    <div ref="viewport" class="graph-viewport">
    <svg ref="svg" role="img" aria-label="Observed BGP paths. Arrow keys pan; plus and minus zoom; Home fits." tabindex="0" :viewBox="`0 0 ${projection.bounds.width} ${projection.bounds.height}`" :style="{ minWidth: fitted ? '0' : `${projection.bounds.width}px`, height: fitted ? 'min(60vh, 600px)' : undefined, minHeight: fitted ? '0' : undefined }" @wheel="wheel" @keydown="key" @pointerdown="down" @pointermove="move" @pointerup="up" @pointercancel="up">
      <g :transform="contentTransform">
        <!-- Pan/zoom only changes the outer transform. Reuse each child until
             its projection, label or route emphasis actually changes. -->
        <path v-for="edge in projection.edges" :key="edge.key" v-memo="[edge, edgeDimmed(edge)]" :d="`M ${projection.byId.get(edge.from)!.x} ${projection.byId.get(edge.from)!.y} L ${projection.byId.get(edge.to)!.x} ${projection.byId.get(edge.to)!.y}`" class="graph-edge" :data-relation="edge.relation" :class="{ dimmed: edgeDimmed(edge) }"><title>{{ `AS${edge.from} → AS${edge.to}: ${edge.relation.replaceAll('_', ' ')}; observed adjacency; original hops ${edge.fromOriginalPosition} → ${edge.toOriginalPosition}${edge.inferred ? '; inferred relationship' : ''}` }}</title></path>
        <g v-for="node in projection.nodes" :key="node.asn" v-memo="[node, nodeDimmed(node.asn), nodeName(node.asn)]" class="graph-node" :transform="`translate(${node.x} ${node.y})`" :class="{ origin: node.asn === origin, truncated: projection.truncatedTerminals.includes(node.asn), dimmed: nodeDimmed(node.asn) }"><title>{{ nodeTitle(node.asn) }}</title><circle r="20"/><foreignObject x="-62" y="26" width="124" height="20"><div xmlns="http://www.w3.org/1999/xhtml" class="graph-node-label" dir="auto">{{ nodeLabel(node.asn) }}</div></foreignObject></g>
      </g>
      <foreignObject v-if="!projection.nodes.length" :x="projection.bounds.width / 2 - 180" :y="projection.bounds.height / 2 - 13" width="360" height="26"><div xmlns="http://www.w3.org/1999/xhtml" class="empty-graph-label">No observed path is available</div></foreignObject>
    </svg>
    </div>
    <div class="graph-caption">
      <p>Observed AS paths{{ projection.edges.length ? ' · known relationships are inferred' : '' }} · {{ projection.nodes.length }}/24 nodes{{ projection.truncated ? ' · view clipped' : '' }}</p>
      <ul v-if="projection.edges.length" class="graph-legend" role="list" aria-label="Relationship legend">
        <li v-for="item in graphRelationshipLegend" :key="item.key" :data-relation="item.key"><span class="relation-sample" aria-hidden="true" />{{ item.label }}</li>
      </ul>
    </div>
    <details v-if="originalPaths.length" :open="originalOpen" class="graph-original" @toggle="toggleOriginal">
      <summary>Original route structure{{ projection.omittedPathIndexes.length ? ` · ${projection.omittedPathIndexes.length} omitted from view` : '' }}</summary>
      <ol v-if="originalOpen"><li v-for="(path, index) in originalPaths" :key="index"><span>Route {{ index + 1 }} · prepends retained{{ path.graphEligible ? '' : ' · linear graph unavailable' }}</span><code>{{ originalText(path) }}</code></li></ol>
    </details>
  </div>
</template>

<style scoped>
.bgp-graph {
  /* Moving SVG content must not rerasterize a backdrop blur every frame. */
  backdrop-filter:none;
  background:var(--surface);
}
.graph-node.truncated circle { stroke-dasharray:3 2; }
.graph-viewport { overflow-x:auto; overscroll-behavior-x:contain; background:var(--content); }
.graph-caption { background:var(--content); }
.graph-caption p { margin:0; }
.graph-legend { display:flex; flex-wrap:wrap; gap:6px 16px; margin:8px 0 0; padding:0; list-style:none; }
.graph-legend li { display:flex; align-items:center; gap:6px; color:var(--ink); }
.relation-sample { width:28px; height:2px; flex:none; background:var(--relation-color); mask-image:var(--relation-mask,none); }
.graph-edge { fill:none; stroke:var(--relation-color); stroke-width:1.75; stroke-dasharray:var(--relation-dash,none); vector-effect:non-scaling-stroke; }
.graph-node-label { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
[data-relation='transit_upstream'] { --relation-color:#135f9d; }
[data-relation='peer'] { --relation-color:#963a09; --relation-dash:8 4; --relation-mask:repeating-linear-gradient(90deg,#000 0 8px,transparent 8px 12px); }
[data-relation='customer'] { --relation-color:#236335; --relation-dash:11 3 3 3; --relation-mask:repeating-linear-gradient(90deg,#000 0 11px,transparent 11px 14px,#000 14px 17px,transparent 17px 20px); }
[data-relation='sibling'] { --relation-color:#743892; --relation-dash:4 3 2 3; --relation-mask:repeating-linear-gradient(90deg,#000 0 4px,transparent 4px 7px,#000 7px 9px,transparent 9px 12px); }
[data-relation='unknown'] { --relation-color:#4d5963; --relation-dash:1 3; --relation-mask:repeating-linear-gradient(90deg,#000 0 1px,transparent 1px 4px); }
.dark [data-relation='transit_upstream'] { --relation-color:#83c4ff; }
.dark [data-relation='peer'] { --relation-color:#ffb477; }
.dark [data-relation='customer'] { --relation-color:#94dcaa; }
.dark [data-relation='sibling'] { --relation-color:#dbacf8; }
.dark [data-relation='unknown'] { --relation-color:#b6c1ca; }
@media (forced-colors:active) {
  .graph-edge { stroke:CanvasText; }
  .relation-sample { forced-color-adjust:none; background:CanvasText; }
}
/* Route focus dims the geometry while every ASN label remains readable. */
.graph-node.dimmed { opacity:1; }
.graph-node.dimmed circle { opacity:.25; }
.graph-viewport svg { max-width:none; }
.graph-original { border-top:1px solid var(--line); padding:14px 24px; font-size:11px; color:var(--secondary); }
.graph-original summary { cursor:pointer; min-height:24px; }
.graph-original ol { margin:16px 0 0; padding-left:18px; }
.graph-original li + li { margin-top:16px; }
.graph-original code { display:block; overflow-wrap:anywhere; margin-top:8px; font-size:10px; line-height:1.7; }
</style>
