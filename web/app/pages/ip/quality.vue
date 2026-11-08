<script setup lang="ts">
const { data, error, loading, current } = useAtlas()
const layers = computed(() => data.value?.quality ? Object.entries(data.value.quality.layers) : [])
const reason = (value: string) => value.replaceAll('_', ' ')
</script>

<template>
  <AtlasView title="Quality" subtitle="Signals & context" :query="current" :loading="loading" :error="error" :synthetic="data?.synthetic">
    <div v-if="data" class="quality-layout">
      <div class="glass edge-glow score-panel"><p class="eyebrow">Quality</p><p class="score-value">{{ data.quality?.score ?? '—' }}<span v-if="data.quality?.score != null">/ 100</span></p><h2>{{ data.quality?.score == null ? 'Unrated' : 'Assessment available' }}</h2><p>{{ data.quality?.score == null ? 'Insufficient assessment coverage. An unlisted address is not a clean address.' : `${data.quality.confidence} confidence · evidence-based context` }}</p></div>
      <div class="quality-detail"><section class="glass detail-panel"><h2>Observed reasons</h2><div v-if="data.quality?.reasons.length" class="chips"><span v-for="flag in data.quality.reasons" :key="flag" class="reason-chip">{{ reason(flag) }}</span></div><p v-else>No positive reason is recorded. Safety is unknown.</p><p class="muted">Network classifications alone are not evidence of abuse.</p></section><section class="glass detail-panel"><h2>Risk contributions</h2><dl class="layer-list"><div v-for="[layer, contribution] in layers" :key="layer"><dt>{{ layer === 'neighbors' ? '/24 neighbors' : layer }}</dt><dd>{{ contribution == null ? 'Unknown' : `${(contribution * 100).toFixed(2)}%` }}</dd></div></dl></section></div>
    </div>
  </AtlasView>
</template>
