<script setup lang="ts">
import { parseInput } from '~/lib/query'
const props = defineProps<{ initial?: string; compact?: boolean }>()
const text = ref(props.initial ?? '')
const error = ref('')
watch(() => props.initial, value => { text.value = value ?? '' })
async function submit() {
  error.value = ''
  try {
    const input = parseInput(text.value)
    await navigateTo(`/ip/${input.kind === 'asn' ? 'asn' : 'overview'}?q=${encodeURIComponent(input.canonical)}`)
  } catch { error.value = 'Enter a valid IP address or public ASN.' }
}
</script>

<template>
  <form class="search-form" :class="{ compact }" @submit.prevent="submit">
    <div class="edge-glow search-surface" :class="{ 'has-error': error }">
      <span class="edge-accent" aria-hidden="true" />
      <label class="sr-only" for="atlas-query">IP address or ASN</label>
      <UInput id="atlas-query" v-model="text" placeholder="IP address or ASN" size="xl" autocomplete="off" autocapitalize="off" spellcheck="false" :aria-invalid="Boolean(error)" :aria-describedby="error ? 'search-error' : undefined" :ui="{ root: 'query-root', base: 'query-input' }" />
      <UButton type="submit" size="lg" aria-label="Look up address" class="search-submit">Explore <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true" focusable="false" fill="none" stroke="currentColor" stroke-width="1.3"><path d="M4 12 12 4M4 4h8v8" /></svg></UButton>
    </div>
    <p v-if="error" id="search-error" role="alert" class="inline-error">{{ error }}</p>
  </form>
</template>
