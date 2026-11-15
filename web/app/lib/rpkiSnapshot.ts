import type { RPKIAnswer } from './via3.ts'

/** These are results observed in a validated snapshot, never a live check. */
export function rpkiSnapshotTiming(row: RPKIAnswer, now: number): { expired: boolean; observedAt: string; validUntil: string } | null {
  if (row.status === 'unavailable' || row.observedAt == null || row.validUntil == null) return null
  return { expired: now >= row.validUntil, observedAt: snapshotTime(row.observedAt), validUntil: snapshotTime(row.validUntil) }
}

function snapshotTime(seconds: number): string {
  const date = new Date(seconds * 1000)
  // The binary contract permits safe integer Unix seconds. Keep unusually large
  // verified timestamps readable without throwing outside JavaScript's Date range.
  return Number.isFinite(date.getTime()) ? date.toISOString().replace('T', ' ').replace('.000Z', ' UTC') : `${seconds} seconds since Unix epoch`
}

/** A suspended tab refreshes its labels immediately when it becomes visible. */
export function trackSnapshotTime(update: (seconds: number) => void, target: Pick<Document, 'addEventListener' | 'removeEventListener'> = document): () => void {
  const refresh = () => update(Date.now() / 1000)
  refresh()
  const timer = setInterval(refresh, 1000)
  target.addEventListener('visibilitychange', refresh)
  return () => { clearInterval(timer); target.removeEventListener('visibilitychange', refresh) }
}
