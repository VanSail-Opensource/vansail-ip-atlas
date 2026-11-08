# Data model — schema 3, contract revision 1

`docs/binary-format-via3.md` fixes serialized widths; this document fixes their
meaning. The initial unimplemented schema is frozen here without pretending
that contract fixtures are a real-source database. No mutable global build state
or untyped record map is permitted after input decoding.

## Internal records and normalization

A versioned tagged union distinguishes location, network mapping, exact risk,
explicit-prefix risk, ASN risk, relationships, paths and VRPs. Each typed member
carries its applicable `netip.Addr`/`netip.Prefix`/ASN, verified item/snapshot
publication time, evidence family, reviewed coverage, reliability and private
lineage ID. Inapplicable fields cannot be supplied through a generic map.
Normalize mapped IPv6 to IPv4. Mapping is factual coverage, never an assessment
that an address is safe. Evidence families, source IDs and publication proofs
are private and never serialized into public records.

Canonical internal risk scopes are `exact_ip`, `prefix`, `asn`; path facts use
`path`, relationship facts `asn_edge`. An adapter explicitly maps a reviewed
source field to a typed record; source-schema fields are not the public schema.
Legacy `exact`, `exact-ip`, `provider_transit`, `native_or_broadcast`,
`ip_assignment_mode`, `scanner`, `c2`, and `cloudflare_proxyip` cannot become new
public field names. Canonical source scope normalization is owned by the source
policy. Source country/registration semantics must be declared, not guessed.

Public snapshots are already field-specifically merged before binary encoding.
Resolve geography by the scoring contract, retain every current origin, resolve
usage conflicts to unknown, and keep separate exact/prefix/ASN/neighbor layers.
An absent more-specific observation does not erase a valid broader factual
mapping. A withdrawn or stale input does remove its prior influence and rebuild
dependent records, dictionaries, aggregates and inherited overlays.

## Presence and enums

A bit set means the corresponding fact was assessed or explicitly supplied.
Zero storage without its bit means unknown. An explicit false boolean, score 0,
dictionary string ID 0 and coordinate 0 are valid present values. Unset reference
storage uses `NONE,NONE`; remaining unset field storage is zero. Every reader
validates that a kind sets only applicable presence bits.

| Bit | Meaning | Applicable kinds |
|---:|---|---|
| 0 | physical country | geo |
| 1 | registration country | geo |
| 2 | region | geo |
| 3 | city | geo |
| 4 | coordinates and precision | coordinates |
| 5 | usage type | usage |
| 6 | assignment mode | usage |
| 7 | anycast boolean | usage |
| 8 | IPv4 directed-broadcast boolean | usage |
| 9 | numeric quality score | quality |
| 10 | exact weighted risk contribution | quality |
| 11 | explicit-prefix weighted contribution | quality |
| 12 | ASN weighted contribution | quality |
| 13 | neighbor weighted contribution | quality |
| 14 | reason flags | quality, ASN |
| 15 | network identity record | network |
| 16 | network/ASN name | network, ASN |
| 17 | organization | network, ASN |
| 18 | ISP | network |
| 19 | complete current MOAS origin list | network, BGP origins |
| 20 | RPKI result | RPKI |
| 21 | observed `/24` profile | IPv4 `/24` |
| 22 | observed aggregate quality | IPv4 `/24` |
| 23 | contextual ASN risk/band | ASN |
| 24 | bounded ASN prefix-page directory | ASN |
| 25 | customer cone | ASN |
| 26 | transit degree | ASN |
| 27 | network class | ASN, Tier-1 |
| 28 | cross-snapshot stability state | ASN, Tier-1 |
| 29 | retained BGP path | BGP paths |
| 30 | directed relationship | BGP relationships |
| 31 | ASN registration country | ASN |

Each Class C cell has its own u8 presence mask defined in the binary contract;
it does not reinterpret the global u32 bit positions.

Usage enum: `0 unknown,1 residential,2 business,3 mobile,4 datacenter,5 hosting,
6 education,7 government`. Assignment enum: `0 unknown,1 native,
2 broadcast_or_routed`. Assignment, anycast and directed broadcast are independent;
country disagreement, a proxy reason or an IPv4 last octet cannot prove them.
An unknown enum never supplies an affirmative classification.

Country is a present ISO-3166-1 alpha-2 code encoded as
`1 + (first_ASCII-65)*26 + (second_ASCII-65)`. Zero means unknown and is absent.
The parser must validate a reviewed assigned country code before encoding;
syntactic pairs such as `AA` and fallback `ZZ` are not real countries. Region and
city are sanitized dictionary strings, subordinate to the chosen physical
country. Registration country is a separate fact and never substitutes for a
physical location.

## Quality and reasons

The approved `release-scope-v2` amendment (2026-11-08) makes numeric quality
optional for production release. A production snapshot may contain no numeric
scores while retaining supported positive reasons and observed contributions.
That state is explicitly unrated; it is not a clean assessment. This amendment
uses the existing null/presence representation and changes no VIA3 schema or
scoring-model revision.

Numeric quality is IPv4-only in this version. Publishing a non-null score
requires complete coverage and all four layers exactly as
`configs/scoring.yaml`/`docs/scoring.md` specify.
`quality_status=unrated` means `quality=null`, never 0 or 100. An assessed score
has presence bit 9; status assessed without that bit, or unrated with it, is
invalid. Confidence 0 is unrated,1 low,2 medium,3 high. Missing coverage does not
erase a positive reason or a positively observed layer contribution.

Four contributions encode the weighted terms of total risk, not a reweighted
distribution that sums to 100%. Store integer millionths, rounding half-up once
after full-precision calculation. The integer score is calculated independently
from the unrounded formula. Layers that remain unknown are null with unset bits.
No source counts, support IDs, raw evidence or probability claim is public.

Reason bits in order are:

| Bit | Canonical reason |
|---:|---|
| 0 | malware |
| 1 | botnet |
| 2 | command_control |
| 3 | abuse |
| 4 | fraud |
| 5 | scanning |
| 6 | spam |
| 7 | tor |
| 8 | vpn |
| 9 | proxy |
| 10 | datacenter |
| 11 | hosting |
| 12 | asn_context |
| 13 | subnet_context |

Bits 14–31 are reserved zero. Internal signals `c2`, `scanner`,
`cloudflare_proxyip` map to `command_control`, `scanning`, `proxy` before family
dedupe and encoding. Correlated subscription repositories remain one family.
Tor/VPN/proxy/datacenter reasons do not assert criminal activity. Reason absence
in a positive-only source is unknown, not a clean observation.

## Geography, network and graph semantics

Coordinates belong to the selected winning-city family and are never averaged.
Quantize to 0.001 degrees, nearest with exact halves away from zero; preserve the
less precise of the observed precision and the encoded grid. Country/region
centroids cannot become city markers. Anycast suppresses city/map display; the
compiler must omit a suppressed city coordinate, rather than shipping a hidden
misleading point. `/ip/overview` is the single geographic/map owner.

Origins are ascending, unique ASN sets. A network with multiple origins never
selects a primary origin by accident. RPKI validates each `(prefix,origin)`;
valid, invalid and not_found require a current complete VRP snapshot. An
unavailable snapshot remains unavailable. ASN-wide risk stays contextual and
capped; no customer's risk is copied from its provider.

Original BGP ASN segments retain ordered hops/prepends and nonlinear markers.
Display-only collapsing keeps an index map to original segments and never
manufactures an edge. Adjacency observation and directed relationship inference
are separate flags. Unknown/conflicting model edges remain unknown, never peer.
The graph projects the retained routes within 24 nodes/two protected hops/three
backbone exits. Clipping is route-contiguous and visibly truncated; unrelated
gaps never acquire a merged SVG trunk. Tier-1 classes and stability are derived
from each snapshot under `configs/tier1.yaml`, not a membership allowlist.

`/ip/quality` owns score/reasons/contributions, `/ip/class-c` owns its sparse
observations rendered into 256 cells, `/ip/asn` owns ASN context, and `/ip/bgp`
owns observed paths/relationships. Other routes link to these canonical views.

## Public strings and prohibited data

Allowed public strings are sanitized network/organization/ISP labels, region,
city, country codes and the fixed enum labels. Normalize to NFC, trim whitespace,
collapse internal whitespace, reject invalid UTF-8/control/bidi-control text,
remove URI/email/domain/credential-bearing tokens, and truncate safely at a
UTF-8 boundary to 256 bytes. If no safe label remains, omit it. Text cannot carry
hidden source identity. Public source names/IDs/URLs, per-source records,
collector identities, subscription URI/path/credentials, hostnames, domains,
ports, protocols, latency, timezone, postal and continent are never serialized.
The permitted BGP ASN sequences are unrelated to forbidden subscription paths.
OSM tile attribution is the independent map condition, not IP-source provenance.

## Typed compilation boundary

`internal/via3.PublicRecord` is a schema-3 tagged union of the twelve public fact
kinds. `CompilePartition` derives dictionaries/pages; `Build` derives the router
and immutable manifest. It accepts at most 32768 records and 32 MiB estimated
input per partition, then enforces the deployed object profile. A production
build requires the caller's independent source/capability gate before compilation
and before manifest emission; the assembler itself does not certify sources.

Input rows are complete field-wise fused boundary states, not raw source deltas.
The producer must materialize every relevant prefix/exact/usage-anycast change.
Resolving a parent's state using its base-address point lookup is invalid when
that point has a more-specific descendant. Source-to-boundary materialization
and full-scale external merge/spill remain integration work; this in-memory
typed API does not establish the full-dataset runner budget.

An empty `GeoData` row explicitly preserves unknown at that key. Compile-only
`CoordinateData.Unknown=true` emits the existing all-zero coordinate row, with
no wire-version change; nonzero values in such a row are rejected. Anycast
cross-fact validation resolves complete prefix entities, excluding descendants,
and rejects known city/coordinates where the applicable anycast fact is true.
It requires correct fused tombstones instead of inventing parent facts. A
more-specific explicit non-anycast entity may retain its own evidenced city.
Partition/source ordering is deterministic. Multiple paths for one origin must
have unambiguous private ranks; equal ranks are rejected rather than inheriting
input order. Those ranks are not public evidence counts.

## Browser query contract

`fixtures/contracts/queries.json` is the shared Go/TypeScript syntax corpus.
`tools/query_contract` provides contract implementations/tests without a runtime
service. Query address syntax matches Go `net/netip`; source decoders separately
require public global addresses. User queries for private/special literals are
valid syntax and produce unknown facts if not mapped; they trigger no probing.

* Input is at most 128 UTF-8 bytes before trimming. Trim ASCII space, tab, CR, LF,
  form-feed and vertical-tab only. Reject remaining controls, Unicode whitespace,
  zone IDs, bracketed addresses, hostnames, URLs, CIDRs and malformed addresses.
* IPv4 is four decimal octets, no leading zeros except `0`. IPv6 uses the Go
  canonical lowercase/longest-zero-run form; IPv4-mapped IPv6 normalizes to IPv4.
* ASN accepts decimal digits or case-insensitive `AS` plus decimal digits;
  leading zeros are removed. ASN 0,23456,64496–65551,65552–131071,
  4200000000–4294967295 are reserved/documentation/private and rejected. Public
  acceptance ranges are therefore 1–23455,23457–64495,131072–4199999999.
* Raw query is at most 1024 UTF-8 bytes and has only `q` and optional `origin`.
  Percent decoding is strict UTF-8; malformed escapes/encoding, unknown keys,
  empty keys, repeated keys (including percent-aliased ones), empty values and
  empty `&` components are invalid. `+` decodes as ASCII space, once. Missing
  `q` on a subview redirects to `/ip`; `origin` without `q` is invalid.
* A valid IP submission goes to `/ip/overview`; ASN goes to `/ip/asn`. Subview
  navigation preserves canonical `q`. ASN `q` on overview/quality/class-c redirects
  to `/ip/asn`. IPv6 Class C is explicitly not applicable, not an input failure.
* `origin` is allowed only for an IP `q` on `/ip/bgp`, uses the ASN syntax/ranges
  above, and normalizes to `AS<number>`. It is syntactically validated before
  requesting data. Membership is checked only after the relevant current
  prefix's complete origin set loads. A nonmember gives `origin_not_member`
  without choosing another origin or changing the query.
* Without `origin`, IP BGP selects the lowest numeric origin deterministically,
  while displaying all origins in the selector. An empty/unknown origin set
  stays unknown. No selection changes stored graph layout or original paths.

Invalid syntax stays on the current route with an inline error and makes no
query-specific request. Missing `q`, invalid syntax, unavailable facts and
nonmember `origin` are distinct states. Reserved routes remain unimplemented.
