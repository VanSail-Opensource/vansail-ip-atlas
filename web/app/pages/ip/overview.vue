<script setup lang="ts">
import { hasMapLocation } from '~/lib/via3'
const { overview: data, error, loading, current } = useAtlas()
const facts = computed(() => data.value ? [
  ['Country', data.value.geo?.country], ['Region', data.value.geo?.region], ['City', data.value.usage?.anycast === true ? null : data.value.geo?.city],
  ['Registration country', data.value.geo?.registrationCountry],
  ['ISP', data.value.network?.isp], ['Usage', data.value.usage?.type], ['Assignment', data.value.usage?.assignment],
  ['Anycast', data.value.usage?.anycast == null ? null : data.value.usage.anycast ? 'Yes' : 'No'],
  ['Directed broadcast', data.value.usage?.directedBroadcast == null ? null : data.value.usage.directedBroadcast ? 'Yes' : 'No'],
] : [])
const hasMap = computed(() => hasMapLocation(data.value))
</script>

<template>
  <AtlasView title="Overview" subtitle="Place & identity" :query="current" :loading="loading" :error="error" :synthetic="data?.synthetic">
    <div v-if="data" class="overview-grid">
      <div class="glass edge-glow fact-panel"><span class="edge-accent" aria-hidden="true" /><dl class="fact-list"><div v-for="[label, value] in facts" :key="label ?? ''"><dt>{{ label }}</dt><dd>{{ value ?? 'Unknown' }}</dd></div></dl></div>
      <div class="glass map-panel"><ClientOnly><LazyGeoMap v-if="hasMap" :latitude="data.geo!.latitude!" :longitude="data.geo!.longitude!" /><div v-else class="map-empty"><svg viewBox="0 0 52 52" aria-hidden="true" focusable="false"><circle cx="26" cy="26" r="21" /><circle cx="26" cy="26" r="14" /><circle cx="26" cy="26" r="6" /></svg><p>{{ data.usage?.anycast ? 'Anycast has no single location.' : 'No evidenced city location.' }}</p></div></ClientOnly><p class="map-caption">{{ hasMap ? 'Approximate area · city-level coordinates' : 'Unknown locations stay unknown' }}</p></div>
    </div>
  </AtlasView>
</template>
