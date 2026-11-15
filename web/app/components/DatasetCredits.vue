<script setup lang="ts">
import { loadDatasetCredits, type CreditDocument } from '~/lib/datasetCredits'
const route = useRoute()
const release = useState<{ releaseId: string; validUntil: number; synthetic: boolean } | null>('atlas-release-info', () => null)
const verifiedCredits = useState<CreditDocument | null>('atlas-dataset-credits', () => null)
const pinned = computed(() => route.path.replace(/\/+$/, '') === '/ip' ? undefined : release.value?.releaseId)
const details = ref<HTMLDetailsElement>()
const document = shallowRef<CreditDocument | null>(null)
const loading = ref(false), error = ref(false)
let request: AbortController | undefined
let serial = 0
async function load() {
  const run = ++serial
  request?.abort()
  request = new AbortController()
  document.value = null; loading.value = true; error.value = false
  try {
    const cached = verifiedCredits.value
    const value = cached && cached.release_id === pinned.value ? cached : await loadDatasetCredits(pinned.value, AbortSignal.any([request.signal, AbortSignal.timeout(10_000)]))
    if (run === serial) document.value = value
  } catch { if (run === serial && !request.signal.aborted) error.value = true }
  finally { if (run === serial) loading.value = false }
}
function toggle(event: Event) {
  if ((event.target as HTMLDetailsElement).open) void load()
  else { serial++; request?.abort(); loading.value = false }
}
watch([pinned, verifiedCredits], () => {
  document.value = null
  const cached = verifiedCredits.value
  if (cached && cached.release_id === pinned.value) {
    serial++; request?.abort(); loading.value = false; error.value = false
    document.value = cached
    if (cached.entries.length && details.value) details.value.open = true
  } else if (details.value?.open) void load()
})
onBeforeUnmount(() => { serial++; request?.abort() })
</script>

<template>
  <div class="dataset-credit-group">
  <p v-if="document?.mode === 'production' && document.entries.length" class="dataset-credit-links" aria-label="Included dataset credits" data-testid="visible-dataset-credits">
    <a v-for="entry in document.entries" :key="JSON.stringify(entry)" :href="entry.url" target="_blank" rel="noopener noreferrer" referrerpolicy="no-referrer"><img v-if="entry.logo && document.verifiedLogos?.[entry.logo.sha256]" :src="document.verifiedLogos[entry.logo.sha256]" :alt="entry.logo.alt" class="dataset-logo" decoding="async">{{ entry.name }}</a>
  </p>
  <details ref="details" class="dataset-credits" data-testid="dataset-credits" @toggle="toggle">
    <summary>Dataset credits</summary>
    <div class="credits-content" aria-live="polite">
      <p v-if="loading">Loading credits…</p>
      <p v-else-if="error" role="status">Dataset credits could not be verified. Please try again.</p>
      <p v-else-if="document?.mode === 'synthetic'">Synthetic preview. No third-party IP datasets are included.</p>
      <p v-else-if="document && document.entries.length === 0">No dataset attribution is required for this release.</p>
      <ul v-else-if="document">
        <li v-for="entry in document.entries" :key="JSON.stringify(entry)" data-testid="dataset-credit">
          <a :href="entry.url" target="_blank" rel="noopener noreferrer" referrerpolicy="no-referrer">{{ entry.name }}</a>
          <p>{{ entry.text }}</p>
          <a v-if="entry.license_url" :href="entry.license_url" target="_blank" rel="noopener noreferrer" referrerpolicy="no-referrer">License</a>
        </li>
      </ul>
    </div>
  </details>
  </div>
</template>

<style scoped>
.dataset-credit-group { color:var(--secondary); max-width:38rem; text-align:left; }
.dataset-credit-group:has(details[open]) { flex:1 0 100%; max-width:100%; order:3; }
.dataset-credit-links { display:flex; flex-wrap:wrap; gap:.4rem 1rem; margin-bottom:.6rem; }
.dataset-credit-links a { display:inline-flex; align-items:center; gap:.45rem; }
.dataset-logo { max-width:8rem; max-height:2.5rem; width:auto; height:auto; object-fit:contain; }
summary { cursor:pointer; width:fit-content; color:var(--ink); border-radius:.3rem; }
summary:focus-visible { outline:2px solid var(--accent); outline-offset:.3rem; }
.credits-content { margin-top:1rem; padding:1.2rem; border:1px solid var(--line); border-radius:1rem; background:var(--surface); line-height:1.65; overflow-wrap:anywhere; }
ul { list-style:none; padding:0; margin:0; } li + li { margin-top:1.5rem; }
a { color:var(--accent); text-decoration:underline; text-underline-offset:.18em; } p { margin:0; }
</style>
