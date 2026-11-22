<script setup lang="ts">
const { quality: data, error, loading, current } = useAtlas()
const risk = computed(() => data.value?.observedRisk)
const layers = computed(() => risk.value ? Object.entries(risk.value.layers) : [])
const displayedScore = computed(() => risk.value?.score == null ? '—' : risk.value.score === 0 ? '<1' : risk.value.score)
const reason = (value: string) => value.replaceAll('_', ' ')
</script>

<template>
  <AtlasView title="Observed risk" subtitle="Signals & context" :query="current" :loading="loading" :error="error" :synthetic="data?.synthetic">
    <div v-if="data" class="quality-layout">
      <div class="glass edge-glow score-panel"><span class="edge-accent" aria-hidden="true" /><p class="eyebrow">Observed risk</p><p class="score-value">{{ displayedScore }}<span v-if="risk?.score != null">/ 100</span></p><h2>{{ risk?.score == null ? 'Unrated' : 'Observed evidence' }}</h2><p>{{ risk?.score == null ? 'No scored positive evidence. Safety is unknown.' : 'Higher means more observed adverse evidence, not a probability.' }}</p><p v-if="risk?.score != null" class="muted">{{ risk.confidence }} evidence confidence · {{ risk.coverage.status }} assessment coverage</p></div>
      <div class="quality-detail"><section class="glass detail-panel"><h2>Observed reasons</h2><div v-if="risk?.reasons.length" class="chips"><span v-for="flag in risk.reasons" :key="flag" class="reason-chip">{{ reason(flag) }}</span></div><p v-else>No positive reason is recorded. Safety is unknown.</p><p class="muted">Network classifications alone are not evidence of abuse.</p></section><section class="glass detail-panel"><h2>Risk contributions</h2><dl class="layer-list"><div v-for="[layer, contribution] in layers" :key="layer"><dt>{{ layer === 'neighbors' ? '/24 neighbors' : layer }}</dt><dd>{{ contribution == null ? 'Unknown' : `${(contribution * 100).toFixed(2)} points` }}</dd></div></dl></section></div>
    </div>
  </AtlasView>
</template>
