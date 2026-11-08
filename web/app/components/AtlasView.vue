<script setup lang="ts">
defineProps<{ title: string; subtitle: string; query: string; loading: boolean; error: string; synthetic?: boolean }>()
</script>

<template>
  <section class="view-page">
    <SearchInput :initial="query" compact />
    <div class="view-heading"><div><p class="eyebrow">{{ subtitle }}</p><h1>{{ title }}</h1></div><span v-if="synthetic" class="demo-label">Synthetic preview</span></div>
    <p v-if="loading" class="status-panel glass" role="status">Opening the atlas…</p>
    <div v-else-if="error" class="status-panel glass" role="alert"><h2>Lookup unavailable</h2><p>{{ error }}</p></div>
    <slot v-else />
  </section>
</template>
