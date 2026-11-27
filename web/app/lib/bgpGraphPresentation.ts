export const graphRelationshipLegend = [
  { key: 'transit_upstream', label: 'Upstream' },
  { key: 'peer', label: 'Peer' },
  { key: 'customer', label: 'Customer' },
  { key: 'sibling', label: 'Sibling' },
  { key: 'unknown', label: 'Unknown' },
] as const

export type GraphIdentity = { asn: number; name: string | null; organization: string | null }
export type GraphNodeName = { asn: number; label: string }
export const maxAdditionalGraphNames = 23 // At most 24 visible nodes, including the already looked-up origin.

export function graphIdentityName(identity?: GraphIdentity): string | undefined {
  return identity?.name?.trim() || identity?.organization?.trim() || undefined
}

// Layout remains fixed. Exports use the HTML label's available space too, but
// have no browser text-overflow to do the clipping for them.
export function fitGraphLabel(label: string, width: number, measure: (value: string) => number): string {
  if (measure(label) <= width) return label
  const ellipsis = '…'
  if (measure(ellipsis) > width) return ''
  let prefix = ''
  for (const { segment } of new Intl.Segmenter().segment(label)) {
    if (measure(prefix + segment + ellipsis) > width) break
    prefix += segment
  }
  return prefix.trimEnd() + ellipsis
}
