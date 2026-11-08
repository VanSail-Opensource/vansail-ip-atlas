<script setup lang="ts">
const { data, error, loading, current, prefixBusy, loadPrefixes } = useAtlas()
const offsets = ref<Record<number, number>>({})
watch(current, () => { offsets.value = {} })
async function page(asn: number, cursor: number) { if (await loadPrefixes(asn, cursor)) offsets.value = { ...offsets.value, [asn]: cursor } }
</script>

<template>
  <AtlasView title="Autonomous systems" subtitle="Network context" :query="current" :loading="loading" :error="error" :synthetic="data?.synthetic">
    <p v-if="data && !data.asns.length" class="glass status-panel">No origin is evidenced for this query.</p>
    <div v-else-if="data" class="asn-list"><article v-for="asn in data.asns" :key="asn.asn" class="glass edge-glow asn-card"><div class="section-top"><div><p class="eyebrow">AS{{ asn.asn }}</p><h2>{{ asn.name ?? 'Network name unknown' }}</h2></div><NuxtLink :to="`/ip/bgp?q=AS${asn.asn}`" class="text-link">Observed routes ↗</NuxtLink></div><dl class="asn-facts"><div><dt>Organization</dt><dd>{{ asn.organization ?? 'Unknown' }}</dd></div><div><dt>ASN risk</dt><dd>{{ asn.risk == null ? 'Unknown' : asn.riskBand }}</dd></div><div><dt>Customer cone</dt><dd>{{ asn.customerCone ?? 'Unknown' }}</dd></div><div><dt>Transit degree</dt><dd>{{ asn.transitDegree ?? 'Unknown' }}</dd></div></dl><h3>Prefixes</h3><ul v-if="asn.prefixes.length" class="prefix-list"><li v-for="prefix in asn.prefixes" :key="prefix">{{ prefix }}</li></ul><p v-else class="muted">No current prefix listing.</p><div v-if="asn.prefixCursor != null || offsets[asn.asn]" class="prefix-pagination"><button v-if="offsets[asn.asn]" class="plain-button" :disabled="prefixBusy" @click="page(asn.asn, 0)">First page</button><button v-if="asn.prefixCursor != null" class="plain-button" :disabled="prefixBusy" @click="page(asn.asn, asn.prefixCursor)">Next page</button></div></article></div>
  </AtlasView>
</template>
