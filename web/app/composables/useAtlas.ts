import { AtlasClient, type LookupAnswer, type OverviewAnswer, type RiskView, type ClassCView, type ClassCAnswer } from '~/lib/via3'
import { resolve, validateOrigin } from '~/lib/query'
import { loadDatasetCredits, type CreditDocument } from '~/lib/datasetCredits'
import { trackSnapshotTime } from '~/lib/rpkiSnapshot'

let atlas: AtlasClient | undefined
export function useAtlas() {
  const route = useRoute()
  const releaseInfo = useState<{ releaseId: string; validUntil: number; synthetic: boolean } | null>('atlas-release-info', () => null)
  const verifiedCredits = useState<CreditDocument | null>('atlas-dataset-credits', () => null)
  const result = shallowRef<LookupAnswer | OverviewAnswer | RiskView | ClassCView | null>(null)
  const data = computed(() => result.value && 'bgp' in result.value ? result.value : null)
  const overview = computed(() => result.value && 'geo' in result.value ? result.value : null)
  const quality = computed(() => result.value && 'observedRisk' in result.value ? result.value : null)
  const grid = computed(() => result.value && 'profile' in result.value ? result.value : null)
  const classC = shallowRef<ClassCAnswer | null>(null)
  const error = ref('')
  const loading = ref(false)
  const current = ref('')
  const origin = ref<number | null>(null)
  const prefixBusy = ref(false)
  const now = ref(Date.now() / 1000)
  let active: AbortController | undefined
  let pendingLookup: AbortController | undefined
  let serial = 0
  let interval: ReturnType<typeof setInterval> | undefined
  let stopClock: (() => void) | undefined
  let ready = false
  function invalidate() {
    releaseInfo.value = null
    verifiedCredits.value = null
    serial++
    active?.abort()
    result.value = null
    classC.value = null
    loading.value = false
    error.value = 'This atlas release is no longer eligible. A verified current release is required.'
  }

  async function load(background = false) {
    // A time-label update or background verification must not unmount a valid
    // page, resetting graph focus/pan or the selected ASN prefix page.
    const retained = background && result.value && Date.now() / 1000 < result.value.validUntil ? result.value : null
    if (!retained) {
      releaseInfo.value = null
      verifiedCredits.value = null
      result.value = null
      classC.value = null
    }
    const run = ++serial
    active?.abort()
    active = new AbortController()
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
    loading.value = !retained
    const controller = active
    pendingLookup = controller
    try {
      atlas ??= new AtlasClient()
      atlas.removeEventListener('invalidate', invalidate)
      atlas.addEventListener('invalidate', invalidate)
      let answer: LookupAnswer | OverviewAnswer | RiskView | ClassCView
      switch (path) {
        case '/ip/overview': answer = await atlas.overview(state.q, active.signal); break
        case '/ip/quality': answer = await atlas.risk(state.q, active.signal); break
        case '/ip/class-c': answer = await atlas.classCView(state.q, active.signal); break
        default: answer = await atlas.lookup(state.q, active.signal)
      }
      let pendingClassC: ClassCAnswer | null = null
      if (run !== serial) return
      if (Date.now() / 1000 >= answer.validUntil) throw new Error('release_expired')
      origin.value = null
      if (state.origin) {
        if (!('bgp' in answer)) throw new Error('invalid_origin')
        origin.value = Number(state.origin.slice(2))
        validateOrigin(origin.value, answer.bgp.origins)
      }
      if ('profile' in answer) {
        pendingClassC = answer.profile
      }
      // Reviewed credits are part of a production release. Verify their exact
      // release document before showing facts that depend on those datasets.
      if (!answer.synthetic) {
        const credits = await loadDatasetCredits(answer.releaseId, AbortSignal.any([active.signal, AbortSignal.timeout(10_000)]))
        if (run !== serial) return
        if (credits.mode !== 'production') throw new Error('release_credits')
        verifiedCredits.value = credits
      }
      if (Date.now() / 1000 >= answer.validUntil) throw new Error('release_expired')
      if (!retained || retained.releaseId !== answer.releaseId || retained.q !== answer.q || ('bgp' in retained) !== ('bgp' in answer)) {
        result.value = answer
        classC.value = pendingClassC
      }
      releaseInfo.value = { releaseId: answer.releaseId, validUntil: answer.validUntil, synthetic: answer.synthetic }
    } catch (cause) {
      if (run !== serial || active.signal.aborted) return
      const code = cause instanceof Error ? cause.message : ''
      error.value = code.includes('origin_not_member') ? 'This origin does not announce the selected prefix.'
        : code.includes('expir') ? 'This release has expired. A current atlas is required.'
          : 'The atlas could not be verified. Please try again when a complete release is available.'
      releaseInfo.value = null
      verifiedCredits.value = null
      result.value = null
      classC.value = null
      atlas?.clear()
    } finally {
      if (pendingLookup === controller) pendingLookup = undefined
      if (run === serial) loading.value = false
    }
  }
  function resume() { if (document.visibilityState === 'visible') { atlas?.clear(); void load(true) } }
  async function loadGraphNames(asns: readonly number[], signal: AbortSignal) {
    const answer = data.value
    if (!atlas || !active || !answer) return []
    const run = serial
    const names = await atlas.graphNames(asns, answer.releaseId, AbortSignal.any([active.signal, signal, AbortSignal.timeout(5000)]))
    return run === serial && data.value?.releaseId === answer.releaseId ? names : []
  }
  async function loadPrefixes(asn: number, cursor: number) {
    if (!atlas || !active || prefixBusy.value) return false
    const run = serial
    prefixBusy.value = true
    try {
      const page = await atlas.prefixes(`AS${asn}`, cursor, active.signal)
      if (run !== serial || !data.value) return false
      result.value = { ...data.value, asns: data.value.asns.map(item => item.asn === asn ? { ...item, prefixes: page.prefixes, prefixCursor: page.nextCursor } : item) }
      return true
    } catch {
      if (run === serial && !active.signal.aborted) invalidate()
      return false
    } finally { prefixBusy.value = false }
  }
  watch(() => route.fullPath, () => { if (import.meta.client && ready) void load() })
  onNuxtReady(() => {
    ready = true
    stopClock = trackSnapshotTime(value => {
      now.value = value
      if (result.value && value >= result.value.validUntil) invalidate()
    })
    void load()
    interval = setInterval(() => {
      // A slow foreground lookup is already checking the current release.
      if (!pendingLookup || pendingLookup.signal.aborted) void load(true)
    }, 60_000)
    document.addEventListener('visibilitychange', resume)
  })
  onBeforeUnmount(() => {
    serial++
    active?.abort()
    if (interval) clearInterval(interval)
    stopClock?.()
    document.removeEventListener('visibilitychange', resume)
    atlas?.removeEventListener('invalidate', invalidate)
  })
  return { data, overview, quality, grid, classC, error, loading, current, origin, prefixBusy, now, loadPrefixes, loadGraphNames, reload: () => load() }
}
