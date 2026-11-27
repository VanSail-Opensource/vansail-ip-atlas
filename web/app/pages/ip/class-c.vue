<script setup lang="ts">
const { grid: data, classC, error, loading, current } = useAtlas()
const focused = ref(0)
const ipv6 = computed(() => current.value.includes(':'))
const mean = computed(() => {
  const profile = classC.value
  return profile ? (profile.scoreSum / profile.totalUnits).toFixed(ipv6.value ? 5 : 2).replace(/\.?0+$/, '') : '0'
})
const selected = computed(() => classC.value?.cells[focused.value])
const cells = ref<HTMLButtonElement[]>([])
function move(event: KeyboardEvent, index: number) {
  const steps: Record<string, number> = { ArrowLeft: -1, ArrowRight: 1, ArrowUp: -16, ArrowDown: 16 }
  let next = index
  if (event.key in steps) next = Math.min(255, Math.max(0, index + steps[event.key]!))
  else if (event.key === 'Home') next = event.ctrlKey ? 0 : index - index % 16
  else if (event.key === 'End') next = event.ctrlKey ? 255 : index - index % 16 + 15
  else return
  event.preventDefault(); focused.value = next; cells.value[next]?.focus()
}
</script>

<template>
  <AtlasView :title="ipv6 ? 'IPv6 subnet risk' : 'Class C'" :subtitle="ipv6 ? 'The surrounding /48' : 'The surrounding /24'" :query="current" :loading="loading" :error="error" :synthetic="data?.synthetic">
    <section v-if="classC?.unit === 'ipv6-/64'" class="glass edge-glow detail-panel subnet-summary" aria-label="IPv6 subnet risk summary">
      <span class="edge-accent" aria-hidden="true" />
      <div class="section-top"><h2>{{ classC.prefix }}</h2><span class="muted">IPv6 /48</span></div>
      <dl class="layer-list">
        <div><dt>Mean observed risk</dt><dd data-testid="subnet-risk-mean">{{ mean }} / 100</dd></div>
        <div><dt>/64 blocks with exact observations</dt><dd>{{ classC.observedCount }} / {{ classC.totalUnits }}</dd></div>
        <div><dt>/64 blocks with positive risk</dt><dd>{{ classC.positiveCount }}</dd></div>
      </dl>
      <p class="muted">Each /64 contributes its highest exact-IP risk contribution. Blocks without observations count as zero, not as assessed safe.</p>
    </section>
    <div v-else-if="classC" class="class-layout"><section class="glass edge-glow grid-panel"><span class="edge-accent" aria-hidden="true" /><div class="section-top"><h2>{{ classC.prefix }}</h2><span class="muted">{{ classC.observedCount }} observed</span></div><div role="grid" aria-label="256 addresses in the /24" aria-rowcount="16" aria-colcount="16" class="ip-grid"><div v-for="row in 16" :key="row" role="row" class="ip-grid-row"><button v-for="column in 16" :key="column" :ref="element => { if (element) cells[(row - 1) * 16 + column - 1] = element as HTMLButtonElement }" role="gridcell" :tabindex="focused === (row - 1) * 16 + column - 1 ? 0 : -1" :aria-label="`${classC.cells[(row - 1) * 16 + column - 1]!.ip}, ${classC.cells[(row - 1) * 16 + column - 1]!.observed ? 'observed' : 'unknown'}`" :aria-selected="focused === (row - 1) * 16 + column - 1" :class="{ observed: classC.cells[(row - 1) * 16 + column - 1]!.observed, positive: classC.cells[(row - 1) * 16 + column - 1]!.reasons.length }" @focus="focused = (row - 1) * 16 + column - 1" @click="focused = (row - 1) * 16 + column - 1" @keydown="move($event, (row - 1) * 16 + column - 1)" /></div></div><p class="muted">Mean observed risk {{ mean }} / 100 across all 256 addresses. Missing scores count as zero.</p><p class="muted">Arrow keys to explore · unobserved is not assessed</p></section><aside v-if="selected" class="glass detail-panel cell-detail"><p class="eyebrow">Selected address</p><h2>{{ selected.ip }}</h2><p>{{ selected.observed ? 'Observed' : 'Not observed' }}</p><p>Observed risk {{ selected.observedRiskScore }} / 100</p><p>{{ selected.usage === 'unknown' ? 'Usage unknown' : selected.usage }}</p><div class="chips"><span v-for="flag in selected.reasons" :key="flag" class="reason-chip">{{ flag.replaceAll('_', ' ') }}</span></div><NuxtLink :to="`/ip/overview?q=${encodeURIComponent(selected.ip)}`" class="text-link">Open address ↗</NuxtLink></aside></div>
  </AtlasView>
</template>
