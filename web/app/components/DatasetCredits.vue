<script setup lang="ts">
import { loadDatasetCredits, type CreditDocument } from '~/lib/datasetCredits'
const route = useRoute()
const release = useState<{ releaseId: string; validUntil: number } | null>('atlas-release-info', () => null)
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
    const value = await loadDatasetCredits(pinned.value, AbortSignal.any([request.signal, AbortSignal.timeout(10_000)]))
    if (run === serial) document.value = value
  } catch { if (run === serial && !request.signal.aborted) error.value = true }
  finally { if (run === serial) loading.value = false }
}
function toggle(event: Event) {
  if ((event.target as HTMLDetailsElement).open) void load()
  else { serial++; request?.abort(); loading.value = false }
}
watch(pinned, () => { document.value = null; if (details.value?.open) void load() })
onBeforeUnmount(() => { serial++; request?.abort() })
</script>

<template>
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
</template>

<style scoped>
.dataset-credits { color:var(--secondary); max-width:38rem; text-align:left; }
.dataset-credits[open] { flex:1 0 100%; max-width:100%; order:3; }
summary { cursor:pointer; width:fit-content; color:var(--ink); border-radius:.3rem; }
summary:focus-visible { outline:2px solid var(--accent); outline-offset:.3rem; }
.credits-content { margin-top:1rem; padding:1.2rem; border:1px solid var(--line); border-radius:1rem; background:var(--surface); line-height:1.65; overflow-wrap:anywhere; }
ul { list-style:none; padding:0; margin:0; } li + li { margin-top:1.5rem; }
a { color:var(--accent); text-decoration:underline; text-underline-offset:.18em; } p { margin:0; }
</style>
