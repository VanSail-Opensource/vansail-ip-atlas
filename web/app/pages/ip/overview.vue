<script setup lang="ts">
const { overview: data, error, loading, current } = useAtlas()
const facts = computed(() => data.value ? [
  ['Country', data.value.geo?.country],
  ['Registration country', data.value.geo?.registrationCountry],
  ['Matched prefix', data.value.network?.prefix],
  ['Usage', data.value.usage?.type],
] as const : [])
</script>

<template>
  <AtlasView title="Overview" subtitle="Place & identity" :query="current" :loading="loading" :error="error" :synthetic="data?.synthetic">
    <div v-if="data" class="glass edge-glow fact-panel">
      <span class="edge-accent" aria-hidden="true" />
      <dl class="fact-list">
        <div v-for="[label, value] in facts" :key="label"><dt>{{ label }}</dt><dd>{{ value ?? 'Unknown' }}</dd></div>
      </dl>
    </div>
  </AtlasView>
</template>
