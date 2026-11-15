<script setup lang="ts">
import type { RPKIAnswer } from '~/lib/via3'
import { rpkiSnapshotTiming } from '~/lib/rpkiSnapshot'

const props = defineProps<{ rows: RPKIAnswer[]; now: number }>()
const snapshots = computed(() => props.rows.map(row => ({ ...row, timing: rpkiSnapshotTiming(row, props.now) })))
</script>

<template>
  <section v-if="rows.length" class="glass detail-panel tier1-list rpki-snapshots" aria-labelledby="rpki-snapshots-title">
    <h2 id="rpki-snapshots-title">Origin-specific RPKI</h2>
    <p class="muted">Results describe the recorded snapshot, not a live authorization check.</p>
    <div v-for="row in snapshots" :key="row.origin" class="rpki-snapshot" :data-rpki-origin="row.origin">
      <p><strong>AS{{ row.origin }}</strong> · <template v-if="row.timing">Snapshot result: {{ row.status.replaceAll('_', ' ') }}<span v-if="row.timing.expired" class="rpki-expired" role="status"> · Expired snapshot</span></template><template v-else>RPKI unavailable</template></p>
      <dl v-if="row.timing" class="rpki-times"><div><dt>Observed</dt><dd>{{ row.timing.observedAt }}</dd></div><div><dt>Snapshot expiry</dt><dd>{{ row.timing.validUntil }}</dd></div></dl>
    </div>
  </section>
</template>

<style scoped>
.rpki-snapshot { margin-block-start: 1rem; }
.rpki-snapshot p { margin-block: .35rem; }
.rpki-expired { font-weight: 650; }
.rpki-times { display: flex; flex-wrap: wrap; gap: .5rem 1.5rem; margin: .5rem 0 0; font-size: .875rem; }
.rpki-times div { display: grid; gap: .15rem; }
.rpki-times dt { font-weight: 600; }
.rpki-times dd { margin: 0; overflow-wrap: anywhere; }
</style>
