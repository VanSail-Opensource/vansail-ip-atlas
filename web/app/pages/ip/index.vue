<script setup lang="ts">
import { motion } from 'motion-v'
import { resolve } from '~/lib/query'
const route = useRoute()
let ready = false
function applyQuery() {
  const state = resolve('/ip', window.location.search.slice(1))
  if (state.state === 'redirect') void navigateTo(`${state.route}?${state.query}`, { replace: true })
}
onNuxtReady(() => { ready = true; applyQuery() })
watch(() => route.fullPath, () => { if (ready) applyQuery() })
</script>

<template>
  <section class="hero">
    <motion.div :initial="false" :animate="{ opacity: 1, y: 0 }" :transition="{ duration: 0.45 }" class="hero-inner">
      <p class="eyebrow">A clearer view of the network</p>
      <h1>Every address.<br><span>A little more context.</span></h1>
      <p class="hero-copy">Explore an IP address or ASN. Geography, quality, and the routes between.</p>
      <SearchInput />
      <p class="hero-footnote">Synthetic preview · IPv4 &amp; IPv6 · private by design</p>
    </motion.div>
    <div class="hero-orbit" aria-hidden="true"><div /><div /><div /></div>
  </section>
</template>
