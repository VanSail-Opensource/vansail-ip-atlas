# Private incremental materialization

The compiler can reuse unchanged spatial work after actual normalized records
change. Reuse is optional and cannot qualify a source, replace source validation,
or authorize a public candidate. The existing production qualification, Tier-1
observation, current input, final candidate and resource gates still run.

## Dependency boundaries

The private `spatial-cache-v1` inventory records separate dependencies for each stage.

| Domain | Reused work | Required identity |
| --- | --- | --- |
| Seed | Category streams for one original normalized partition | Complete original partition descriptor, including byte hash and counters |
| Scatter | Four-level spatial redistribution for one input partition | Complete ordered input descriptors and parent prefix |
| Raw split | Subdivision required by the distinct raw records before adding ASN roles or coverage | Scope, ordered physical partition descriptors and collection limits. Each hit verifies the current bytes of every input object. |
| Risk | A fitting leaf's ordered exact-address risk events, or its split decision | Scope, ordered descriptors, fit limits, scoring policy and evaluation clock. Shared public geometry also binds the joined roles. |
| Risk input | A fitting leaf's exact-address events across unrelated spatial edits | Exact evidence, prefix-to-origin observations, their canonical order, scope, exact-layer scoring policy and evaluation clock |
| Public | A fitting leaf's public records, or its split decision | Risk dependencies, final global ASN contexts, RPKI completeness, publisher observation time and coverage deadline |
| Compiled | Final public objects and routes for a public partition subtree | Actual complete public-run bytes, scope and actual ASN prefix-provider bytes and index |

All domains additionally bind the executable's actual bytes, compiler limits,
public schema and build mode. No key relies on `Source.Fingerprint` alone.
Changing the compiler, packing limits or implementation therefore creates an
incompatible cache and takes the ordinary cold path.

Seed streams end at original input-partition boundaries. A changed city does not
shift later category chunks. Every source still completes its full strict
normalized walk before any cached category stream is adopted. That walk rebuilds
usage, relationship, known-ASN, edge, exact-record, path and prefix side indexes
from the current state. Withdrawn sources cannot leave a cached side index.

During that same walk, the compiler records which IPv4 and IPv6 seed groups
contain exact evidence or prefix-to-origin observations. The ASN risk pass
can process those groups separately. It keeps every record in a mixed group
and accumulates routed risk in canonical address order. The public pass uses
all original groups and still applies the full record, join and geometry limits.


Spatial reuse retains the existing binary traversal, exact-record deduplication,
encoded fit accounting, path population cap, IPv4 `/24` floor and inherited
prefix behavior. Risk entries contain individual address events in their original
order, with exact floating-point risk values and ordered families and origins.
Replay performs the original additions; it does not combine floating-point sums.
Public streams pass the normal selected-payload validation and sorter/conflict
logic. Their consumed encoded bytes are hashed during replay.

Relationship and Tier-1 results are recomputed through their existing paths.
The spatial public filter emits only kinds 2 through 7 and 9, whose dependencies
are the spatial inputs and the explicitly bound global contexts. It cannot replay
cached ASN, path, relationship or origin-set output. The final compiled cache can
contain those outputs because its key includes the complete current public run;
ASN prefix pages also bind their separate actual provider content.

Compiled misses hash the raw bytes actually consumed by the strict public-run
reader, before buffering or decompression, and verify the expected digest and
length at clean EOF. Rechecking the owned file before removal is an additional
guard; a changed-then-restored file cannot bind different consumed facts to the
original cache key. Compiled restoration validates every object hash, size,
public profile, reference closure and route scope. Object and route registrations use the
normal compiler paths. Shared objects are deduplicated against the current output
inventory, including verification of any existing destination. Historical byte,
file and scratch counters are never copied. The final router is rebuilt.

## Storage and failure behavior

The closed inventory is authenticated, with bounded entries and object metadata.
Every used object is checked against its actual bytes. Imported normalized
objects remain ordinary strict-read inputs; an authenticated cache entry cannot
create a process-local canonical-frame capability. Malformed authenticated
inventories and changed objects fail closed.

The cache's capacity is one quarter of the unchanged total scratch budget. That
capacity includes the previous generation, staging, key and index. The same
aggregate scratch accounting also includes normalized state, spool data, public
runs and candidate output. Optional retention can decline when its bounded
capacity cannot fit; ordinary compilation continues. Cache generation switching
happens only after successful materialization and the final input/resource gates.
A failed build preserves the prior committed generation and does not publish a
partial cache or candidate.

Inline states and states with more than 1,024 original normalized partitions use
the existing coalesced cold path. This avoids multiplying category streams beyond
the existing normalized-object budget. This is a cache eligibility bound, not a
source eligibility rule or an increased resource limit.

## Workspace and benchmark scope

`benchmark-state -prepare` and its timed warm invocation share the same isolated
workspace. They therefore retain the authenticated cache while changing the
required `ceil(normalized_records / 100)` actual Geo.City records. Unchanged
normalized descriptors remain intact; source fingerprints are deliberately
unchanged, so cache correctness requires the actual content identities above.

The encrypted checkpoint transport deliberately excludes both materialization
caches. It transports the existing allowlisted normalized state, history and
receipts. A newly restored job starts cold; no private cache enters public
artifacts or expands the checkpoint allowlist. The local normalized-Geo cold
benchmark explicitly removes both cache directories before every timed build.

Synthetic differential and timing diagnostics do not establish real production
coverage or the hosted 35-minute cold and 8-minute changed-state gates. Those
limits and the full authenticated populations remain unchanged and require
exact-candidate hosted evidence.

The local 400,200-record diagnostic changed exactly 4,002 Geo.City records while
retaining the original source fingerprint. The warm result, fresh changed-state
result and ordinary coalesced fallback produced the same release identifier and
manifest, 602,000 public records, 49 partitions and 1,744,121 output bytes.

| Local diagnostic | Total seconds | Final partition seconds |
| --- | ---: | ---: |
| Baseline preparation | 24.477 | 9.094 |
| Changed state with all reuse layers | 11.047 | 3.739 |
| Fresh changed state | 25.014 | 9.135 |
| Changed state through coalesced fallback | 23.867 | 8.466 |

Mutation took another 0.447 seconds. The warm compiler measured 153,018,368 bytes
peak process RSS and 22,918,270 bytes peak scratch, including both cache
generations. These are one-sample diagnostic measurements on synthetic data,
not hosted production percentiles or capacity certification.
