import { AtlasClient, type LookupAnswer, type ClassCAnswer } from '~/lib/via3'
import { resolve, validateOrigin } from '~/lib/query'

let atlas: AtlasClient | undefined
export function useAtlas() {
  const route = useRoute()
  const data = shallowRef<LookupAnswer | null>(null)
  const classC = shallowRef<ClassCAnswer | null>(null)
  const error = ref('')
  const loading = ref(false)
  const current = ref('')
  const origin = ref<number | null>(null)
  const prefixBusy = ref(false)
  let active: AbortController | undefined
  let serial = 0
  let interval: ReturnType<typeof setInterval> | undefined
  let ready = false
  function invalidate() {
    serial++
    active?.abort()
    data.value = null
    classC.value = null
    loading.value = false
    error.value = 'This atlas release is no longer eligible. A verified current release is required.'
  }

  async function load() {
    const run = ++serial
    active?.abort()
    active = new AbortController()
    data.value = null
    classC.value = null
    error.value = ''
    // Static prerender payloads have no query. Validate the actual raw URL after
    // hydration so repeated/empty parameters survive until the contract parser.
    const raw = window.location.search.slice(1)
    const path = window.location.pathname.replace(/\/+$/, '') || '/'
    const state = resolve(path, raw)
    if (state.state === 'redirect') {
      await navigateTo(`${state.route}${state.query ? `?${state.query}` : ''}`, { replace: true })
      return
    }
    if (state.state !== 'ok' || !state.q) {
      error.value = 'This query is invalid. Enter an IP address or public ASN.'
      loading.value = false
      return
    }
    current.value = state.q
    loading.value = true
    try {
      atlas ??= new AtlasClient()
      atlas.removeEventListener('invalidate', invalidate)
      atlas.addEventListener('invalidate', invalidate)
      const answer = await atlas.lookup(state.q, active.signal)
      if (run !== serial) return
      if (Date.now() / 1000 >= answer.validUntil) throw new Error('release_expired')
      origin.value = null
      if (state.origin) {
        origin.value = Number(state.origin.slice(2))
        validateOrigin(origin.value, answer.bgp.origins)
      }
      if (path === '/ip/class-c') {
        const cells = await atlas.classC(state.q, active.signal)
        if (run !== serial) return
        if (!cells && state.kind === 'ip' && !state.q.includes(':')) {
          const base = state.q.split('.').slice(0, 3).join('.')
          classC.value = { prefix: `${base}.0/24`, observedCount: 0, assessedCount: 0, positiveCount: 0, aggregateScore: null,
            cells: Array.from({ length: 256 }, (_, suffix) => ({ ip: `${base}.${suffix}`, observed: false, score: null, confidence: 'unrated', reasons: [], usage: 'unknown', origins: [] })) }
        } else classC.value = cells
      }
      data.value = answer
    } catch (cause) {
      if (run !== serial || active.signal.aborted) return
      const code = cause instanceof Error ? cause.message : ''
      error.value = code.includes('origin_not_member') ? 'This origin does not announce the selected prefix.'
        : code.includes('expir') ? 'This release has expired. A current atlas is required.'
          : 'The atlas could not be verified. Please try again when a complete release is available.'
      atlas?.clear()
    } finally { if (run === serial) loading.value = false }
  }
  function resume() { if (document.visibilityState === 'visible') { atlas?.clear(); void load() } }
  async function loadPrefixes(asn: number, cursor: number) {
    if (!atlas || !active || prefixBusy.value) return false
    const run = serial
    prefixBusy.value = true
    try {
      const page = await atlas.prefixes(`AS${asn}`, cursor, active.signal)
      if (run !== serial || !data.value) return false
      data.value = { ...data.value, asns: data.value.asns.map(item => item.asn === asn ? { ...item, prefixes: page.prefixes, prefixCursor: page.nextCursor } : item) }
      return true
    } catch {
      if (run === serial && !active.signal.aborted) invalidate()
      return false
    } finally { prefixBusy.value = false }
  }
  watch(() => route.fullPath, () => { if (import.meta.client && ready) void load() })
  onNuxtReady(() => {
    ready = true
    void load()
    interval = setInterval(() => void load(), 60_000)
    document.addEventListener('visibilitychange', resume)
  })
  onBeforeUnmount(() => {
    serial++
    active?.abort()
    if (interval) clearInterval(interval)
    document.removeEventListener('visibilitychange', resume)
    atlas?.removeEventListener('invalidate', invalidate)
  })
  return { data, classC, error, loading, current, origin, prefixBusy, loadPrefixes, reload: load }
}
