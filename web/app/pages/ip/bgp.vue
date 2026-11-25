<script setup lang="ts">
const { data, error, loading, current, origin, now } = useAtlas()
const selected = computed(() => origin.value ?? data.value?.bgp.origins[0] ?? (current.value.startsWith('AS') ? Number(current.value.slice(2)) : null))
function choose(event: Event) {
  const value = (event.target as HTMLSelectElement).value
  void navigateTo(`/ip/bgp?q=${encodeURIComponent(current.value)}&origin=AS${value}`)
}
</script>

<template>
  <AtlasView title="BGP" subtitle="Observed network paths" :query="current" :loading="loading" :error="error" :synthetic="data?.synthetic">
    <div v-if="data"><div class="bgp-controls"><label v-if="data.kind === 'ip' && data.bgp.origins.length">Origin <select aria-label="Select announcing origin" :value="selected" @change="choose"><option v-for="asn in data.bgp.origins" :key="asn" :value="asn">AS{{ asn }}</option></select></label><span v-else class="muted">{{ current }}</span><span class="muted">An AS adjacency does not establish a business relationship.</span></div><BgpGraph v-if="selected != null" :paths="data.bgp.paths" :relationships="data.bgp.relationships" :origin="selected" /><div v-else class="glass status-panel"><h2>No observed origin</h2><p>No current origin or route is evidenced for this address.</p></div><RpkiSnapshots :rows="data.bgp.rpki" :now="now" /><div v-if="data.bgp.tier1.length" class="glass detail-panel tier1-list"><h2>Derived network classes</h2><p v-for="network in data.bgp.tier1" :key="network.asn">AS{{ network.asn }} · {{ network.networkClass.replaceAll('_', ' ') }} · {{ network.stability }}</p></div></div>
  </AtlasView>
</template>
