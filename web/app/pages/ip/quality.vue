<script setup lang="ts">
const { quality: data, error, loading, current } = useAtlas()
const risk = computed(() => data.value?.observedRisk)
const supported = computed(() => Boolean(risk.value && risk.value.confidence !== 'unrated'))
const labels = { exact: 'Exact IP', prefix: 'Prefix', asn: 'ASN context', neighbors: '/24 neighbors' }
const layers = computed(() => risk.value ? (Object.keys(labels) as (keyof typeof labels)[])
  .filter(layer => risk.value?.coverage.layers[layer] !== 'not_applicable')
  .map(layer => ({ name: labels[layer], points: ((risk.value?.layers[layer] ?? 0) * 100).toFixed(2) })) : [])
const displayedScore = computed(() => risk.value?.score === 0 && supported.value ? '<1' : risk.value?.score ?? 0)
const reason = (value: string) => value.replaceAll('_', ' ')
</script>

<template>
  <AtlasView title="Observed risk" subtitle="Signals & context" :query="current" :loading="loading" :error="error" :synthetic="data?.synthetic">
    <div v-if="data" class="quality-layout">
      <div class="glass edge-glow score-panel"><span class="edge-accent" aria-hidden="true" /><p class="eyebrow">Observed risk</p><p class="score-value"><b data-testid="observed-risk-value">{{ displayedScore }}</b><span>/ 100</span></p><h2>{{ supported ? 'Observed evidence' : 'No scored observations' }}</h2><p>{{ supported ? 'Higher means more observed adverse evidence, not a probability.' : 'Missing observations count as zero. This does not establish safety.' }}</p><p class="muted">{{ risk?.confidence ?? 'unrated' }} evidence confidence · {{ risk?.coverage.status ?? 'incomplete' }} assessment coverage</p></div>
      <div class="quality-detail"><section class="glass detail-panel"><h2>Observed reasons</h2><div v-if="risk?.reasons.length" class="chips"><span v-for="flag in risk.reasons" :key="flag" class="reason-chip">{{ reason(flag) }}</span></div><p v-else>No positive reason is recorded.</p><p class="muted">Network classifications alone are not evidence of abuse.</p></section><section class="glass detail-panel"><h2>Risk contributions</h2><dl class="layer-list"><div v-for="layer in layers" :key="layer.name"><dt>{{ layer.name }}</dt><dd>{{ layer.points }} points</dd></div></dl></section></div>
    </div>
  </AtlasView>
</template>
