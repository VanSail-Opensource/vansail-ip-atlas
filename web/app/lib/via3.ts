export type GeoAnswer = { country: string | null; registrationCountry: string | null; region: string | null; city: string | null; latitude: number | null; longitude: number | null; precision: string | null }
export type NetworkAnswer = { prefix: string; name: string | null; organization: string | null; isp: string | null; origins: number[] }
export type UsageAnswer = { type: string; assignment: string; anycast: boolean | null; directedBroadcast: boolean | null }
export type LayerCoverage = 'assessed' | 'unassessed' | 'not_applicable'
export type CoverageAnswer = { status: 'complete' | 'incomplete'; layers: { exact: LayerCoverage; prefix: LayerCoverage; asn: LayerCoverage; neighbors: LayerCoverage } }
export type QualityAnswer = { coverage: CoverageAnswer; score: number | null; confidence: string; reasons: string[]; layers: { exact: number | null; prefix: number | null; asn: number | null; neighbors: number | null } }
export type ASNAnswer = { asn: number; name: string | null; organization: string | null; country: string | null; risk: number | null; riskBand: string; confidence: string; prefixes: string[]; prefixCursor: number | null; customerCone: number | null; transitDegree: number | null; networkClass: string; stability: string }
export type ASNPrefixPage = { asn: number; prefixes: string[]; nextCursor: number | null }
export type RPKIAnswer = { origin: number; status: string; observedAt: number | null; validUntil: number | null }
export type BGPAnswer = { origins: number[]; paths: { origin: number; asns: number[]; visibility: string; graphEligible: boolean; segments: { type: string; asns: number[] }[] }[]; relationships: { from: number; to: number; relation: string; observed: boolean; inferred: boolean }[]; tier1: { asn: number; networkClass: string; stability: string }[]; rpki: RPKIAnswer[] }
export type LookupAnswer = { q: string; kind: 'ip' | 'asn'; releaseId: string; synthetic: boolean; validUntil: number; geo: GeoAnswer | null; network: NetworkAnswer | null; usage: UsageAnswer | null; observedRisk: QualityAnswer | null; asns: ASNAnswer[]; bgp: BGPAnswer }
export type OverviewAnswer = Pick<LookupAnswer, 'q' | 'releaseId' | 'synthetic' | 'validUntil' | 'geo' | 'network' | 'usage'> & { kind: 'ip' }
export type CellAnswer = { ip: string; observed: boolean; coverage: 'complete' | 'incomplete'; observedRiskScore: number | null; confidence: string; reasons: string[]; usage: string; origins: number[] }
export type ClassCAnswer = { prefix: string; cells: CellAnswer[]; observedCount: number; assessedCount: number; positiveCount: number; scoredCount: number; meanObservedRisk: number | null }

/** Only an evidenced city or finer area can support the approximate map. */
export function hasMapLocation(answer: Pick<LookupAnswer, 'geo' | 'usage'> | null | undefined): boolean {
  return answer?.geo?.latitude != null && answer.geo.longitude != null && answer.usage?.anycast !== true &&
    ['city_centroid', 'area', 'city centroid', 'city-centroid', 'finer', 'finer_evidenced_area'].includes(answer.geo.precision ?? '')
}

/** All VIA3 decoding and lookup work stays in one bounded worker. */
export class AtlasClient extends EventTarget {
  private worker: Worker
  private sequence = 0
  private pending = new Map<number, { resolve: (value: unknown) => void; reject: (error: Error) => void; dispose: () => void }>()

  constructor() {
    super()
    this.worker = new Worker(new URL('../workers/atlas.ts', import.meta.url), { type: 'module' })
    this.worker.onmessage = (event: MessageEvent) => {
      const message = event.data
      if (message.event === 'invalidate') { this.dispatchEvent(new CustomEvent('invalidate', { detail: message.reason })); return }
      const request = this.pending.get(message.id)
      if (!request) return
      this.pending.delete(message.id)
      request.dispose()
      if (message.error) request.reject(new Error(message.error))
      else request.resolve(message.answer)
    }
    this.worker.onerror = () => {
      for (const request of this.pending.values()) { request.dispose(); request.reject(new Error('worker')) }
      this.pending.clear()
      this.dispatchEvent(new CustomEvent('invalidate', { detail: 'worker' }))
    }
  }

  private request<T>(action: string, q: string, signal?: AbortSignal, cursor?: number): Promise<T> {
    if (signal?.aborted) return Promise.reject(new DOMException('Aborted', 'AbortError'))
    const id = ++this.sequence
    return new Promise((resolve, reject) => {
      const abort = () => {
        this.pending.delete(id)
        this.worker.postMessage({ action: 'cancel', id })
        reject(new DOMException('Aborted', 'AbortError'))
      }
      signal?.addEventListener('abort', abort, { once: true })
      this.pending.set(id, { resolve: value => resolve(value as T), reject, dispose: () => signal?.removeEventListener('abort', abort) })
      this.worker.postMessage({ action, id, q, cursor })
    })
  }

  lookup(q: string, signal?: AbortSignal): Promise<LookupAnswer> { return this.request('lookup', q, signal) }
  overview(q: string, signal?: AbortSignal): Promise<OverviewAnswer> { return this.request('overview', q, signal) }
  classC(q: string, signal?: AbortSignal): Promise<ClassCAnswer | null> { return this.request('classC', q, signal) }
  prefixes(asn: string, cursor = 0, signal?: AbortSignal): Promise<ASNPrefixPage> { return this.request('prefixes', asn, signal, cursor) }
  clear(): void {
    for (const [id, request] of this.pending) { this.worker.postMessage({ action: 'cancel', id }); request.dispose(); request.reject(new DOMException('Aborted', 'AbortError')) }
    this.pending.clear()
    this.worker.postMessage({ action: 'clear' })
  }
  destroy(): void { this.clear(); this.worker.terminate() }
}
