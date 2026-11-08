<script setup lang="ts">
const mode = useColorMode()
const route = useRoute()
const path = computed(() => route.path.replace(/\/+$/, '') || '/')
const query = computed(() => typeof route.query.q === 'string' ? route.query.q : '')
const links = [ ['Overview', 'overview'], ['Quality', 'quality'], ['Class C', 'class-c'], ['BGP', 'bgp'], ['ASN', 'asn'] ]
const href = (view: string) => `/ip/${view}${query.value ? `?q=${encodeURIComponent(query.value)}` : ''}`
</script>

<template>
  <UApp>
    <div class="atlas-shell">
      <a class="skip" href="#main">Skip to content</a>
      <header class="site-header">
        <NuxtLink to="/ip" class="brand" aria-label="VanSail IP Atlas home"><span class="brand-symbol" aria-hidden="true">V</span><span>VanSail<span class="brand-secondary"> / IP Atlas</span></span></NuxtLink>
        <button class="theme-toggle" aria-label="Toggle color theme" @click="mode.preference = mode.value === 'dark' ? 'light' : 'dark'"><span aria-hidden="true">◐</span></button>
      </header>
      <nav v-if="path !== '/ip'" class="view-nav" aria-label="Atlas views">
        <NuxtLink v-for="[label, view] in links" :key="view" :to="href(view!)" :class="{ selected: path === `/ip/${view}` }">{{ label }}</NuxtLink>
      </nav>
      <main id="main"><NuxtPage /></main>
      <footer class="site-footer"><span>VanSail IP Atlas</span><span>Lookups stay in your browser</span></footer>
    </div>
  </UApp>
</template>
