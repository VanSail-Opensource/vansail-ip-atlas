# BGP and Tier-1 contract, revision 1

This P0 contract defines `configs/tier1.yaml`. The existing 0.80 peer support,
0.98 cone/degree percentiles, two independent families, 12 retained paths,
24 graph nodes, two protected hops and three exits remain unchanged. The new
two-snapshot, 24-to-720-hour stability window and deterministic tie/overflow
rules close previously unspecified behavior. No fixed ASN membership is allowed.
All fixtures in `fixtures/bgp/contract-v1.json` are synthetic engineering data.

## Relationship direction and origins

A normalized directed relationship `(provider, customer)` means that, from the
customer's perspective, its edge toward the provider is `transit_upstream`.
From the provider toward the customer it is `customer`. Peer and sibling are
symmetric. A CAIDA-style `A|B|-1` row means A provides transit to B; `A|B|0` means
peer. Only a certified adapter may map additional publisher relationship codes.
Missing, conflicting or unsupported edges are `unknown`, never peer. Observed
adjacency and inferred business relation are separate facts: a relation does not
create an observed path edge, and path direction cannot reverse a relation.

Every announced prefix retains its sorted set of actual origins. RPKI uses each
origin and the actual announced prefix, not only the queried address. With a
valid, current VRP snapshot, one matching covering VRP whose ASN and maximum
length authorize the announcement yields `valid`; covering VRPs but none that
authorize it yield `invalid`; no covering VRP yields `not_found`. Without that
snapshot the result is `unknown`, not `not_found`. Origins are evaluated
independently, including MOAS and multiple/overlapping VRPs.

## Observed paths

Retain typed original AS_PATH segments, with ASN order and prepend occurrences
unchanged; collector identities remain private. Canonical public linear paths
are oriented from origin outward by reversing the observed collector-to-origin
sequence, not by sorting ASNs. Four-octet reconstruction must follow the MRT
adapter's certified AS4_PATH rules; no truncation to 16 bits. ASN values in
fixtures do not assert production membership.

Non-linear AS_SET or confederation segments never become guessed ordered ASN
edges. Retain them as typed private observations until their public segment
layout is supported, and exclude them from a linear graph. Nonconsecutive loops
are retained in the observation, but excluded from the bounded simple graph;
consecutive prepends may collapse for display with an original-position mapping.
An unavailable linear graph is preferable to invented links.

Canonical path identity includes the original sequence, segment tags and
orientation. Deduplicate identical paths before counting independent visibility;
multiple collectors in one family count once. Rank unique paths per origin by:

1. Fraction of actual adjacencies with known, nonconflicting relationships,
   descending (compare rational counts without floating point).
2. Original AS sequence length ascending, including prepends.
3. Independent current observation family count descending.
4. Canonical original path bytes ascending.

Keep at most 12. Family counts support private ranking only; they are not public
source counts. Reranking is a build operation; focusing a route never rebuilds
the browser graph layout.

## Deterministic bounded graph projection

Build one projection from the retained ranked routes. Collapse only consecutive
prepends for display. Select routes in rank order while checking their **whole**
first-two-hop protection set and the 24-node union budget. The origin is hop zero;
its next two ASNs are protected. If adding a route would exceed that protected
union, omit the route and mark truncation. Never drop a protected hop or connect
across a missing hop to fit more routes.

For selected routes, reserve all protected nodes first. In rank order, append
their contiguous remaining nodes while the union stays within 24 and each
second-hop ASN has at most three distinct next-hop backbone exits. A route
already represented by another route's nodes still contributes only its actual
adjacencies. On reaching either limit, retain its contiguous prefix and mark its
visible terminal as truncated; do not jump to a later existing node. A missing
route or suffix is disclosed by a source-free truncation state.

Tier-1-to-Tier-1 collapse is display-only. Each collapsed segment carries the
exact original contiguous sequence it represents; it is never an observed direct
adjacency. Merge a trunk only when represented original sequences and their
endpoint positions agree. Different gaps sharing a visual column never merge.
Selecting a route changes emphasis only. Relations, original hop positions,
observed/inferred status and truncation remain inspectable and accessible.

The browser implementation is the pure `web/app/lib/bgpGraph.ts` projection,
consumed by `BgpGraph.vue`. It reserves protected sets before filling suffixes,
retains original records without mutation and discloses clipped terminals and
omitted routes. Original typed segments and prepends remain available in a
progressive disclosure. Separate SVG edges retain their original endpoint
positions; only identical actual adjacencies at identical positions share a trunk.
`web/tests/bgpGraph.test.ts` covers long paths, protected-set and exit overflow,
missing intermediate hops, prepends, nonlinear paths, directed unknown/peer
classification, distinct trunks and selection-independent layout. These synthetic
tests do not certify source coverage or the hosted 24-node performance gate.

## Tier-1 population, percentiles and peer core

Required input is a current, certified directed relationship snapshot and at
least two independent current MRT path families. Two collectors from one family
do not qualify. Missing, stale, invalid or conflicting required inputs make
Tier-1 `unknown`; origin mapping or an allowlist cannot replace them.

The percentile population is the set of all public ASN endpoints in the current
normalized relationship snapshot. Include zero-degree endpoints retained by its
schema; exclude reserved/private ASNs and do not add absent ASNs from an
allowlist. For each ASN:

- Upstreams and customers are distinct immediate directed neighbors.
- Transit degree is the number of distinct provider/customer neighbors, excluding
  peer and sibling edges.
- Customer cone is the set reachable by following provider-to-customer edges,
  excluding the starting ASN. Deduplicate nodes reached on multiple paths.
- Sibling edges are not provider/customer edges and do not expand the cone.
- A provider/customer cycle or conflicting incident relation makes affected
  nodes' direction-dependent statistics unknown. A cone reaching such a node is
  also unknown; it cannot be used as a large cone. The population remains fixed,
  and unknown statistic values block classification rather than counting zero.

For each statistic, compute nearest-rank P98 from the entire population's known
values only when all population values are known: sort ascending and take index
`ceil(0.98*N)-1`. Membership meets the threshold when value is at least this
value; ties are included. If a required population statistic is unknown, the
Tier-1 derivation is unknown for that snapshot. This avoids silently shrinking
the denominator to high-visibility ASNs.

The initial peer-core pool contains ASNs with zero upstreams, positive customer
cone, known relations on every observed incident adjacency, P98 cone and degree
thresholds met, and visibility in at least two independent current path families.
Discover a near-complete core by deterministic peeling: with pool size N, every
member must have at least `ceil(0.80*(N-1))` symmetric known peers in the pool.
While this is false, remove the member with the lowest peer degree, breaking ties
by highest numeric ASN, and recompute. Fewer than three remaining members means
no qualified core. The three-member floor is an explicit bootstrap safety rule,
not a hardcoded membership list. Strong connectivity alone is insufficient for
the configured 0.80 support. All survivors must satisfy the other predicates.

Zero observed upstreams alone never produces a candidate. A candidate is an
inference under these inputs, not a claim of worldwide provider-free business
status. Noncandidate classification uses known current inputs: P98 cone and
degree with upstreams is `global_transit`; positive customers otherwise is
`regional_transit`; no customers and at least one upstream is `access_network`;
ambiguous, isolated or missing input is `unknown`.

## Snapshot stability and bootstrap

The current raw candidate predicate must hold in both the current snapshot and
the immediately previous fully eligible snapshot with the same contract/config
hash. Their publisher snapshot clocks must be at least 24 and at most 720 hours
apart. Both snapshots must still be eligible under current freshness/rights
policy. A missing, changed-policy or disqualified intervening snapshot breaks
continuity; do not search backward for a convenient historical success.

On a first snapshot or insufficient separation, a raw candidate is publicly
`unknown` with source-free `pending` stability. On a second qualified observation
it is `tier1_candidate` with `stable` stability. Failure of the current predicate
removes candidacy immediately; historical stability cannot extend it. Missing
required inputs produce `unknown`/`unavailable`. This is snapshot agreement, not
time-smoothed evidence or permanent membership.

## Discovery and cold-build acquisition (C05)

Production MRT remains disabled. Certification may use bounded private fixtures
without enabling production. The executable cold-build plan reserves two source
slots, one selected RIPE RIS-family snapshot and one RouteViews-family snapshot,
downloaded and parsed sequentially under the existing aggregate 1024 MiB MRT
compressed budget. If one source exceeds its share or the aggregate budget,
qualification fails; do not use two collectors from the other family or require
an undocumented warm cache. Revalidated certified cache objects can replace
downloads only when their exact payload/proof identities and eligibility match.

CAIDA discovery uses the current serial-2 index and lexicographically greatest
valid `YYYYMMDD.as-rel2.txt.bz2` name not after the build snapshot cutoff. Resolve
only same-origin bounded index links and then pin the chosen exact asset/hash.
The filename is discovery, **not publication proof**: bind a certified embedded
timestamp or accepted authoritative per-asset metadata to the downloaded bytes.
The current header allowlist is empty, so directory mtime or HTTP Last-Modified
alone cannot qualify age. Failure to establish proof quarantines the source.
No discovery rule by itself grants rights or admission.

RIPE RIS and RouteViews discovery similarly selects one exact current RIB per
family before download, binds its certified snapshot clock to exact bytes and
checks the 720-hour ceiling. Index naming and parser schemas still require
observed full-payload fixture certification. This document does not claim that
the upstream bytes, publication clocks, rights or cold-run resource envelope
have passed. Hosted parser, reverse-path, RPKI, MOAS, route-continuity, overflow,
stability and full-run performance gates remain required by P5/P7.

## BGP4MP replay input and four-octet transition parsing

`ParseMRT` remains the streaming TABLE_DUMP_V2 snapshot parser. Its AS_PATH
encoding is four octets regardless of peer-table ASN width, as required by
[RFC 6396 section 4.3.4](https://www.rfc-editor.org/rfc/rfc6396.html#section-4.3.4).
It never guesses a legacy two-octet encoding; incompatible input fails. A
modern four-octet snapshot ignores AS4_PATH instead of replacing its actual path.

The separate `ParseBGP4MP` API emits bounded private replay events from BGP4MP
and BGP4MP_ET: announcements, withdrawals, session resets and End-of-RIB markers.
It supports two/four-octet ASNs, local/received messages, IPv4/IPv6 transport,
IPv4/IPv6 unicast MP_REACH/MP_UNREACH and the ADDPATH subtypes defined by
[RFC 8050](https://www.rfc-editor.org/rfc/rfc8050.html). Path IDs and direction
survive until replay. Session identity is an opaque transport-tuple hash; peer
addresses, next hops and other raw attributes are discarded. Paths preserve
segment boundaries, sets, confederations and prepends; an AS_SET terminal has
no arbitrarily selected origin. Shared path slices are immutable sink inputs.

For two-octet BGP messages, AS4_PATH reconstruction follows
[RFC 6793 section 4.2.3](https://www.rfc-editor.org/rfc/rfc6793.html#section-4.2.3):
AS_SET contributes one route-selection hop and confederations contribute none;
retain the necessary leading original segments, then append the surviving AS4
segments. Aggregator suppression, overlong AS4 paths, malformed AS4 attributes,
NEW-to-NEW discard and forbidden AS4 confederation segments follow its processing
rules. A reconstructed path exceeding the existing 4096-ASN/255-segment limits
fails. Unsupported AFI/SAFI and enhanced refresh markers fail explicitly instead
of being mistaken for ordinary unicast or silently losing stale-route semantics.

This API is not a RIB reducer. A future disk-backed transactional replay stage
must apply replacement/withdrawal by source session, direction, prefix and path
ID; clear both directions on session resets; and handle snapshot/EOR boundaries
before producing current facts. Snapshot intake still rejects update feeds.
No source rights, publication proof, MRT admission or production gate changes.
Focused synthetic fixtures cover subtype/transport/clock combinations, transition
rules, controls, malformed data and resource/cancellation/sink bounds; the hosted
workflow includes a separate BGP4MP fuzz smoke. Only actual run results establish
hosted acceptance.
