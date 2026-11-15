<script setup lang="ts">
const props = defineProps<{ latitude: number; longitude: number }>()
const container = ref<HTMLElement>()
let map: { remove: () => void } | undefined
onMounted(async () => {
  const L = await import('leaflet')
  await import('leaflet/dist/leaflet.css')
  if (!container.value) return
  const created = L.map(container.value, { scrollWheelZoom: false, attributionControl: true, zoomControl: false }).setView([props.latitude, props.longitude], 8)
  created.attributionControl.setPrefix(false)
  const icon = (path: string) => `<svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true" focusable="false" style="display:block;margin:6px" fill="none" stroke="currentColor" stroke-width="2"><path d="${path}" /></svg>`
  L.control.zoom({ zoomInText: icon('M5 12h14M12 5v14'), zoomOutText: icon('M5 12h14') }).addTo(created)
  L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', { maxZoom: 12, attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>' }).addTo(created)
  L.circle([props.latitude, props.longitude], { radius: 10_000, color: '#39a78b', weight: 1, fillOpacity: 0.12 }).addTo(created)
  map = created
})
onBeforeUnmount(() => map?.remove())
</script>
<template><div ref="container" class="geo-map" role="region" aria-label="Approximate city area map" /></template>
