# VIA3 Binary Format — schema 3, contract revision 1

This is the first byte-level freeze of the previously unimplemented schema 3.
Magic/format/public-schema remain `VIA3`/`3`/`3`. Machine-readable tables and
uncompressed synthetic vectors are in `fixtures/contracts/via3-layouts.json`.
They are contract fixtures, not a compiled real-source database or source
certification. The compressed engineering corpus is now
`fixtures/bin/synthetic-via3.json`, consumed by the Go reader and TypeScript worker;
`fixtures/bin/semantic-hostile-via3.json` contains full-integrity rejection cases.
These local results do not satisfy hosted or production gates. Incompatible changes after this freeze increment the public
schema and add explicit old-version rejection fixtures.

Integers are unsigned little-endian unless marked `i32`. Address bytes are
network-order octets, never an integer in host order. Reserved bytes and unused
bits MUST be zero. No pointers or implicit struct padding are serialized.
Source/provenance, subscription data, collector identity and arbitrary URIs are
prohibited. Observed BGP ASN sequences below are permitted public facts.

## Bounds and framing

| Limit | Exact rule |
|---|---|
| File bytes | `64 <= n < 25165824` (24 MiB is rejected) |
| Descriptors | `1 <= count <= 256` |
| Decoded section | at most 67108864 bytes |
| Sum decoded sections | at most 268435456 bytes |
| Decoder window | at most 8388608 bytes |
| Record/vector count | bounded by validated length and element width |
| Codec | ID 1; one independent Zstandard frame per section |

These are format ceilings, not permission to allocate every section together;
browser/process budgets in `docs/performance.md` also apply. Trained/external
frame dictionaries, concatenated/skippable frames and trailing frame bytes are
forbidden. Frame content size is required and equals descriptor decoded length.
Cancellation terminates decoding; emitted bytes cannot exceed that length.
Hosted stable Chrome must demonstrate supported, bounded decoding before P0
exits. The user-approved C06 amendment uses pinned bundled `fzstd` 0.1.1 with
full frame/window/output/checksum guards in a worker. The wire codec remains
Zstandard ID 1; no remote decoder, alternate codec or legacy browser fallback is
allowed. Native `DecompressionStream('zstd')` is diagnostic only, not a gate.

The deployable Go/browser profile is narrower than the generic inspector:
32 MiB decoded per object, 96 MiB of unique live decoded buffers including cache
and pinned router, 8 MiB materialized answers, 4096 origins, and 49152 retained
path ASNs per answer. One backing buffer shared by query/cache/router pins is
charged once. Query pins are released on success, failure and cancellation.
These limits are checked before decoding/array allocation; a candidate must be
repacked or rejected, never truncated. `atlas inspect -public` enforces the
deployed profile; plain `inspect` retains the generic 64/256 MiB format ceilings.
RSS acceptance still requires measurement of the complete worker/process.

The header is exactly 64 bytes:

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 4 | ASCII `VIA3` |
| 4 | 2 | format version = 3 |
| 6 | 2 | public schema = 3 |
| 8 | 2 | header length = 64 |
| 10 | 2 | shard kind, below |
| 12 | 4 | flags = 0 |
| 16 | 4 | section count |
| 20 | 8 | section table offset = 64 |
| 28 | 8 | exact file length |
| 36 | 8 | sum of decoded lengths |
| 44 | 1 | codec = 1 |
| 45 | 19 | reserved |

Each descriptor is exactly 64 bytes:

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 2 | section ID |
| 2 | 1 | codec = 1 |
| 3 | 1 | flags = 0; all schema-3 sections are required when present |
| 4 | 4 | reserved |
| 8 | 8 | compressed offset |
| 16 | 8 | compressed length, nonzero |
| 24 | 8 | decoded length |
| 32 | 32 | SHA-256 of decoded bytes |

Descriptors are ascending unique section IDs. Unknown IDs are rejected.
The first frame starts at `64 + count*64`. Frames follow descriptor order,
touch end-to-start with no padding/gaps, and end exactly at file length.
This rejects overlaps, hidden bytes and trailing data. Every section listed for
a shard is present, including empty vectors.

## Shared sections and references

`NONE = 0xffffffff`. A nullable two-part reference is either fully valid or
`NONE,NONE`; partial-null references are invalid. Counts never use `NONE`.
Every section below starts with `count:u32,width:u32`, followed by exactly
`count*width` bytes. There is no alignment padding. Blob width is 1.
Overflow-safe arithmetic precedes allocation.

| ID | Name | Width | Row definition |
|---:|---|---:|---|
| 1 | prefix index | 32 | prefix key + local record ordinal |
| 2 | ASN index | 8 | `asn:u32,record:u32`, ascending unique ASN |
| 3 | records | by shard | record table, definitions below |
| 4 | integers | 4 | u32 vector; field-owned semantics |
| 5 | string offsets | 4 | `string_count+1` UTF-8 boundaries |
| 6 | string bytes | 1 | concatenated UTF-8 strings |
| 7 | object directory | 40 | `kind:u16,reserved:u16,file_bytes:u32,sha256:32` |
| 8 | inherited prefixes | 32 | same as section 1 |
| 9 | path segments | 12 | `type:u8,reserved:3,asn_first:u32,asn_count:u32` |
| 10 | class-C cells | 32 | sparse exact-address cells, below |
| 11 | ASN prefixes | 24 | `family:u8,bits:u8,reserved:u16,address:16,reserved:u32` |
| 12 | ASN prefix pages | 16 | `object:u32,first:u32,count:u32,reserved:u32` |

Prefix rows are `family:u8,bits:u8,flags:u16,address:16,record:u32,reserved:u64`
at offsets `0,1,2,4,20,24`. Family is 4 or 6. IPv4 has 12 zero bytes then its
four octets. IPv4-mapped IPv6 is unwrapped before encoding. Host bits are zero.
Flag bit 0 means exact observation and requires length 32 or 128. Other flags
are zero. Full-length explicit prefixes remain distinguishable from exact IPs.
Rows sort by `(family,address bytes,bits,flags)` and are unique; referenced
records exist. RPKI's origin-key extension below is the only exception.

Inherited rows preserve the original broader prefix, never a fabricated shard
boundary prefix. They reference materialized local copies of ancestor facts.
The manifest identifies the shard partition; every overlay contains that
partition. An identical row cannot appear in sections 1 and 8. Withdrawal of an
ancestor rebuilds all dependent overlays; old overlays never become fallback.

`StringRef = dictionary_object:u32,string_id:u32` (8 bytes). A dictionary object
resolves through section 7 to kind 14 in the pinned manifest. `RecordRef =
object:u32,record:u32` (8 bytes), with expected kind specified at the use site.
Object directories sort by `(kind,sha256 bytes)`, are unique, and contain only
referenced objects. Bytes/hash match the pinned manifest. Cyclic cross-object
references are invalid. A router can reference all fact kinds; fact objects
reference dictionaries and the explicit cell/page references below only.
Dictionaries reference no objects. Arbitrary paths/URLs are never encoded.

String offsets start at zero, strictly increase, and end at the byte-blob
length. Strings are nonempty NFC UTF-8, unique and byte-sorted, max 256 bytes.
An empty dictionary has one zero offset. Dictionary IDs are zero-based.
Labels pass `docs/data-model.md` sanitation before interning.

## Shards and records

Field offsets below are bytes. Presence uses `docs/data-model.md`'s u32 mask;
only bits applicable to the record kind are allowed. Absent storage is zero,
except nullable references use `NONE,NONE`. Enums use explicit unknown value 0.

| Kind | Name | Required sections | Record bytes |
|---:|---|---|---:|
| 1 | Router | 1,2,3,4,7 | 16 |
| 2 | Geo | 1,3,7,8 | 24 |
| 3 | Coordinates | 1,3,8 | 16 |
| 4 | Network | 1,3,4,7,8 | 40 |
| 5 | Usage | 1,3,8 | 8 |
| 6 | Quality | 1,3,8 | 32 |
| 7 | IPv4 `/24` | 1,3,7,10 | 24 |
| 8 | ASN | 2,3,7,11,12 | 64 |
| 9 | RPKI | 1,3,8 | 16 |
| 10 | BGP origins | 1,3,4,8 | 16 |
| 11 | BGP paths | 2,3,4,9 | 24 |
| 12 | BGP relationships | 2,3,4 | 16 |
| 13 | Tier-1 | 2,3 | 16 |
| 14 | Dictionary | 5,6 | no record table |

Kinds 2–6 and 9–10 use prefix routing; 8 and 11–13 use ASN routing. Kind 7 has
only IPv4 `/24` keys without overlays. A router has both index types.
RPKI and BGP-origin keys are prefix facts and never set the exact-address flag.

* **Router (16):** `0 destinations_first:u32;4 destinations_count:u16;
  6 reserved:u16;8 reserved:u64`. Section 4 contains object-directory ordinals,
  sorted by kind/hash. At most one destination per kind. Kind 1 cannot be a
  destination: no recursive router fetch. Dictionaries are reached by references,
  never searched globally. One bounded router covers the pinned release.
* **Geo (24):** `0 presence:u32;4 physical_country:u16;
  6 registration_country:u16;8 region:StringRef;16 city:StringRef`.
* **Coordinates (16):** `0 presence:u32;4 latitude:i32;8 longitude:i32;
  12 precision:u8;13 reserved:3`. Coordinates are thousandths of degrees;
  latitude [-90000,90000], longitude [-180000,180000]. Round nearest, exact halves
  away from zero. Precision: 0 unknown,1 country,2 region,3 city centroid,
  4 finer evidenced area. A numeric grid never implies household precision.
* **Network (40):** `0 presence:u32;4 origins_first:u32;8 origins_count:u32;
  12 reserved:u32;16 name:StringRef;24 organization:StringRef;32 isp:StringRef`.
  Section 4 holds ascending unique ASNs per range. Retain all MOAS origins.
  RPKI is per-origin kind 9, never one arbitrary origin's status.
* **Usage (8):** `0 presence:u32;4 usage_type:u8;5 assignment_mode:u8;
  6 bools:u8;7 reserved:u8`. Boolean bits 0 anycast,1 IPv4 directed broadcast;
  remaining bits zero. A true value requires its independent presence bit.
* **Quality (32):** `0 presence:u32;4 reason_bits:u32;8 status:u8;9 score:u8;
  10 confidence:u8;11 reserved:u8;12 exact_contribution:u32;
  16 prefix_contribution:u32;20 asn_contribution:u32;
  24 neighbor_contribution:u32;28 reserved:u32`. Four weighted risk contributions
  are millionths, rounded half-up at serialization only, bounded respectively
  by 550000,180000,150000,120000. Score uses the unrounded formula, range 0–100.
  Status 0 unrated,1 assessed; confidence 0 unrated,1 low,2 medium,3 high.
  Positive reasons survive an unrated score; absent contributions remain absent.
  IPv6 keys cannot carry numeric quality or a `/24` neighbor contribution. Given
  four rounded contributions, a reader accepts only scores possible within
  their combined ±2 millionth rounding interval; it does not reconstruct one
  falsely precise score from rounded layers. The typed compiler validates the
  supplied score against the original unrounded contributions before encoding.
* **IPv4 `/24` (24):** `0 presence:u32;4 cells_first:u32;8 cells_count:u16;
  10 assessed_count:u16;12 positive_count:u16;14 reserved:u16;
  16 dominant_asn:u32;20 aggregate_score:u8;21 confidence:u8;22 reserved:u16`.
  Counts <=256. Only exact observed cells exist; a prefix is never expanded into
  256 facts. Aggregate score requires all 256 cells to be quality-eligible;
  otherwise it is null. Average all 256 integer scores half-up when eligible.
  Dominant ASN is absent on ties or MOAS ambiguity. `/24` distributions
  are computed from its one bounded cell range, without duplicated scalars.
* **ASN (64):** `0 presence:u32;4 asn:u32;8 name:StringRef;
  16 organization:StringRef;24 country:u16;26 risk_band:u8;27 confidence:u8;
  28 risk:u32;32 reason_bits:u32;36 prefix_pages_first:u32;
  40 prefix_pages_count:u32;44 customer_cone:u32;48 transit_degree:u32;
  52 network_class:u8;53 stability:u8;54 reserved:10`. Risk is millionths 0–1000000.
  Bands 0 unknown,1 low (<333334),2 medium (<666667),3 high describe context,
  never criminality. Prefix pages sort in canonical prefix order, <=256 rows per
  page via section 12. A page references kind 8 and a section-11 first/count.
  Page-only objects have empty indexes/records and no further references. This
  permits bounded paging for huge ASN lists without scanning unrelated ASNs.
* **RPKI (16):** `0 presence:u32;4 origin_asn:u32;8 status:u8;
  9 maximum_length:u8;10 reserved:6`. Status 0 unavailable,1 valid,2 invalid,
  3 not_found. Missing/stale VRPs are unavailable; not_found requires a complete
  current VRP snapshot. Prefix keys may repeat only for contiguous ascending
  origin-ASN runs. The selected actual announcement chooses its exact prefix
  run, then binary-searches origin ASN. An unrelated more-specific RPKI row
  cannot hide that announcement's result; parent results never apply to a
  different more-specific announcement. This clarifies lookup semantics without
  changing any stored bytes or keys. Uniqueness is `(prefix key,origin_asn)`,
  with ascending record ordinals per run.
* **BGP origins (16):** `0 presence:u32;4 origins_first:u32;
  8 origins_count:u32;12 reserved:u32`. Section-4 origins are ascending unique
  and match network mapping whenever both are known. All MOAS origins survive.
* **BGP paths (24):** `0 presence:u32;4 origin_asn:u32;8 segments_first:u32;
  12 segments_count:u16;14 flags:u8;15 visibility_band:u8;16 reserved:u64`.
  Flag bit 0 graph-eligible, other bits zero. Visibility 0 unknown,1 low,2 medium,
  3 high is source-free; raw supporting counts stay private. Segment types:
  1 ordered AS_SEQUENCE,2 AS_SET,3 confederation sequence,4 confederation set.
  Segments refer to section-4 ASN ranges. Sets are unique ascending; sequences
  preserve original prepends. Nonlinear/confederation routes are retained but
  graph-ineligible. At most 12 routes/origin,255 segments/route,4096 ASNs/route.
  ASN index points to the first record of a contiguous origin run; the next
  index record or total count ends that run. Ranking is in `configs/tier1.yaml`.
* **BGP relationships (16):** `0 presence:u32;4 from_asn:u32;8 to_asn:u32;
  12 relation:u8;13 flags:u8;14 reserved:u16`. Relation from `from_asn` perspective:
  0 unknown,1 transit_upstream,2 peer,3 customer,4 sibling. Flag bit 0 observed
  ordered-sequence adjacency, bit 1 supported by the directed relationship model.
  These facts are independent; observed adjacency cannot manufacture a peer.
  ASN-index runs contain unique edges ascending by `to_asn`. Section 4 is empty.
* **Tier-1 (16):** `0 presence:u32;4 asn:u32;8 network_class:u8;
  9 stability:u8;10 reserved:6`. Class 0 unknown,1 tier1_candidate,
  2 global_transit,3 regional_transit,4 access_network. Stability 0 unavailable,
  1 pending,2 stable. No fixed ASN memberships; a first snapshot cannot be stable.
  Exact derivation is in `configs/tier1.yaml`.

A class-C cell is **32 bytes**: `0 suffix:u8;1 presence:u8;2 usage_type:u8;
3 assignment_mode:u8;4 reason_bits:u32;8 score:u8;9 confidence:u8;
10 reserved:u16;12 exact_risk:u32;16 network:RecordRef;24 bools:u8;25 reserved:7`.
Cell presence bits: 0 usage,1 assignment,2 reasons,3 score,4 exact risk,5 network,
6 anycast,7 directed broadcast. Exact risk is unweighted millionths. Network
references require kind 4. Cells within a `/24` range sort by unique suffix.
Absent suffixes stay unknown. Positive count counts nonzero reason flags;
assessed count counts cells with score present. No source/family counts exist.

## Indexing, precedence and determinism

Prefix lookup binary-searches a candidate for each possible prefix length:
at most 33 searches for IPv4 or 129 for IPv6. This is bounded-depth O(log n),
never a full scan. Compare local/inherited candidates by longest prefix, then
exact before a same-length explicit prefix. No match means unknown. An adaptive
radix representation may replace this on-disk index only in a new schema.
The compiler materializes field-specific merge winners into each fact record;
readers do not invent new cross-source/layer merges. Repacking preserves answers.
The router selects one fact object per kind; ASN search is O(log n), and
path/edge runs, prefix pages and `/24` ranges have explicit bounds.

Records sort by their first referring index key. Identical records may be
interned only when the lowest referring key determines position. Vectors append
in record order without unreferenced elements. Dictionaries and object
directories use their ordering above. Compression uses pinned settings: level 3,
one compressor worker, content size and frame checksum enabled, <=8 MiB window.
No build timestamp, random seed or filesystem path enters VIA3. Identical public
facts/config and the same pinned compressor produce identical bytes.

## Validation and errors

Verify the manifest whole-object hash first. Then check in order: input length
(`length`); magic/version/header/reserved (`version` or `header`); table/count/
offset arithmetic and contiguous framing (`bounds`); kinds/required sections/
widths/flags (`schema`); bounded frame decode (`codec` or `decompression_limit`);
decoded length/hash (`integrity`); UTF-8/vector bounds/sorting/masks/enums/
references (`record`). Missing references are `missing_object`; expired releases
are `expired`. No partially validated record is exposed, and no failure causes
fallback to another release or codec.
Deployment working-set/answer/profile rejection is `resource_limit`, separate
from generic format corruption. Known but contradictory network/BGP origin
sets are `record`. A stored RPKI result applies only to its actual announcement
prefix/origin; storage overlays do not make a parent's validation valid for a
different more-specific announcement.

JavaScript checks u64 values as BigInt against format limits before Number
conversion. An advertised decoded length is not a trusted allocation hint.
Check arithmetic before multiplication/addition, including `first+count` and
`count*width`. Parse in a bounded worker and cancel obsolete query work. Schema 3
has no optional/ignorable sections. Old readers reject changed schema versions.

P0 vectors cover every record width, address encoding, exact/prefix keys,
dictionary ID 0, explicit false booleans, score 0 versus unrated, reason bits,
all shard IDs and corruption classes. Executed compressed parity and overlay
lookup remain P1 requirements; uncompressed vectors do not claim those gates.
