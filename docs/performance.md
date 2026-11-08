# Performance and capacity contract v3.2 (visible graph population)

This freezes C06/C11 before collecting a baseline. No budget is raised. Synthetic
contract tests measure correctness only; they do not establish full-dataset capacity.

## Absolute gates and measurement population

| Gate | Requirement |
|---|---:|
| Standard private hosted runner | 2 vCPU, 8 GiB RAM, 14 GiB physical disk |
| Cold full build | Under 35 minutes |
| Warm changed build | Under 8 minutes |
| Warm unchanged build including expiry checks | Under 3 minutes |
| Whole-process-group peak RSS | Below 6656 MiB |
| Peak scratch | Below 10240 MiB |
| Complete generated static tree | At most 3072 MiB |
| Go indexed lookup p95 | Below 2 microseconds |
| Cached browser lookup p95 | Below 15 milliseconds |
| Typical cold-query compressed payload | Below 400 KiB |
| Initial executed JS, gzip | Below 200 KiB |
| Mobile LCP | Below 2.5 seconds |
| Lab interaction latency / INP estimate | Below 200 milliseconds |
| CLS over complete interaction script | Below 0.1 |
| BGP interaction | At least 50 frames/second at 24 nodes |
| Pages physical inventory | Fewer than 18500 files, every asset below 24 MiB |

Use nearest-rank percentiles. Record raw samples, count, p50/p95/p99, extrema,
allocation count, compressed/decoded input sizes, record/path counts, revision,
all config/input hashes, runner image/CPU/memory/disk and actual tool/browser
versions. All reported thresholds are strict except the explicitly inclusive static
tree cap. An absent metric or idle page is `unmeasured`, never passed.

Build scenarios each run three times before the first production baseline:

1. Cold full: empty eligible cache and scratch, identical pinned fresh inputs.
2. Warm changed: fixed one-percent source-record mutation with deterministic dirty
   partition set and unchanged evaluation clock.
3. Warm no-change: identical inputs, but all freshness/withdrawal/config checks run.
4. Clock advance: cross snapshot and subscription-item expiry without changing bytes.
5. Withdrawal: remove one contributing source and regenerate every dependent layer.

Report every sample and gate the maximum build RSS/scratch/runtime. Do not hide a
failed sample in an average. Before relative regression gates are enabled, collect
at least ten accepted hosted runs on the same versioned real-input corpus. Absolute
gates apply immediately. Relative thresholds require a reviewed baseline amendment.

The 24-node graph workload uses explicit Fit so its adaptive world bounds fit
both viewport axes. Before, after and every second of each ten-second trusted
pan/zoom/focus phase, all 24 complete circle bounds must be inside the SVG and
the actual screen clip. A DOM count cannot qualify an off-screen population.
Keep the original alternating zoom-in/zoom-out pair (`deltaY=-50`, then `+50`),
event cadence and 50-FPS gate. The default readable canvas, four viewport widths,
nonoverlapping circle/label bounds and full-world export are separate UI checks.
Idle scheduler and injected-CSS diagnostics remain ineligible for acceptance.

## Process and disk accounting

Sample the entire process group at 100 ms, including Go, Node, decompression,
external sort and packaging children; use cgroup peak counters where available and
report sampling blind spots. Linux `resource.getrusage(RUSAGE_CHILDREN)` alone is not
simultaneous process-group peak RSS. Set Go memory target to 5120 MiB but enforce the
whole-group RSS abort independently; `GOMEMLIMIT` is not an RSS bound.

Record physical disk high-water and free-space low-water, including checkout,
toolchains, dependency stores, downloads, expansion, sort runs, eligible/private
caches, current/previous objects and upload staging. Scratch and output ceilings
are not independent reservations within 14 GiB. Abort before physical free space
falls below 1024 MiB and before either RSS/scratch ceiling. Polling is a safety
signal, not permission to allocate an unbounded archive between samples. Stream
expanded inputs, cap concurrent decoders and reclaim sort scratch before packaging.

## Lookup and browser protocol

Fix a versioned 10000-query corpus with IPv4/IPv6 exact/LPM, MOAS, sparse/dense ASN,
deep inherited overlays and unknown values. Run 1000 untimed warmups then at least
100000 timed Go lookups, reporting latency and allocations. For browser hot lookup,
run at least 1000 lookups after 100 warmups, across three independent browser
contexts. Cold lookups use a fresh HTTP/IndexedDB cache per query; report at least
100 stratified queries. Hash verification and decompression are included when cold.
Record object-read counts to prove bounded routing; do not time a precomputed answer.

The typical IP payload is the p95 of all required compressed response bytes for the
fixed non-graph IP corpus, including pointer, manifest, router, shared dictionaries,
overlays and every initially requested object. Count revalidation/control requests;
report the maximum and graph/map payload separately. Initial JS includes all
executed entry and worker dependencies, gzipped individually at level 9 and summed.
Lazy map/graph imports are measured separately when activated.

Use branded current-stable Chrome (`channel: chrome`) and record its exact build.
Run 30 independent cold navigations per 320/390/1280/1440 width in light and dark
themes. Mobile uses DPR 2, 4x CPU slowdown, 150 ms RTT, 1.6 Mbps down/750 Kbps up;
desktop uses native CPU with the same documented network model. Script search,
navigation, map activation, Class C keyboard selection, and 24-node graph pan/zoom/
path selection for 10 seconds each. Collect LCP and CLS with buffered observers and
interaction-event durations; label lab INP estimates separately from field INP.
Measure frame intervals throughout the graph script, not just an idle animation.

## Bundled codec and browser memory (approved C06 amendment)

Only Zstandard codec ID 1 is permitted. On 2026-11-08 the user explicitly approved
a pinned, bounded bundled Zstandard decoder after actual Chrome rejected native
`DecompressionStream('zstd')`. This amends the native-only mechanism, not the VIA3
codec or public schema. The sole implementation is `fzstd@0.1.1`, pinned with registry
integrity in the lockfile, wrapped by `web/app/lib/zstd.ts`. No CDN, runtime download,
alternate codec, native fallback or enrichment API is allowed. Upstream's documented
streaming interface is inspected and its unchecked frame checksum is independently
verified by the wrapper; see https://github.com/101arrowz/fzstd.

`node tools/hosted/codec-bundled.mjs` is the acceptance probe. It bundles the exact
local dependency and wrapper, runs golden hashes plus malformed/window/output tests
in actual Chrome, and fails nonzero on any failure. `reports/codec-bundled.json`
records the local passing run and exact bundle hash. `codec-probe.mjs` and its failed
`reports/codec.json` preserve the native diagnostic; native support is no longer a
gate after this explicit amendment. Local Chrome results are not hosted acceptance.

The pinned compressor is `github.com/klauspost/compress v1.20.3`, level 3, concurrency
1, 8 MiB maximum window, frame content size present, checksum enabled and no external
dictionary. Small frames use single-segment encoding; frames above 8 MiB must remain
non-single-segment with an explicit <=8 MiB window. The empty-frame probe is codec
syntax coverage uses a manually checksummed empty frame verified by the Go reference.
Freeze the production
writer's exact settings and bytes with P1 Go/TS golden fixtures.

Header/descriptor asset length must be strictly below 24 MiB before allocation;
decoded section <=64 MiB, decoded shard total <=256 MiB and frame window <=8 MiB.
Browser worker memory envelope is 384 MiB, one in-flight object, 32 MiB decoded LRU
cache and 128 MiB IndexedDB compressed cache. Evict LRU objects before admitting
new ones, and reject a request whose hard working set exceeds the envelope. Streaming
output bounds alone do not prove native decoder window memory bounds: inspect the
frame header before decoding. A cancelled/obsolete query cannot publish a result.

### Explicit browser deployment profile amendment

The 2026-11-08 working-set audit found that a 32 MiB LRU alone did not bound live
shards retained by a query. The browser deployment profile therefore adds stricter
admission limits without raising any budget or changing VIA3 record semantics:

| Browser admission limit | Exact ceiling |
|---|---:|
| Decoded bytes per object | 32 MiB |
| Live query decoded bytes, including LRU and pinned router | 96 MiB |
| Serialized answer | 8 MiB |
| Origins retained in one answer | 4096 |
| Total retained AS_PATH ASN elements in one answer | 49152 |

These are recorded in `configs/web.yaml` and
`build.storage.browser_deploy_profile` in the source build configuration. The Go
compiler, release preflight and browser reader must enforce the same deployment
profile. The standalone format inspector still permits the format's 64 MiB section
and 256 MiB container limits; such a container may be valid VIA3 while ineligible
for this browser deployment. Profile violations cause a resource error before
allocating the excessive output, never partial origins, truncated paths or fabricated
unknown facts. The planner must repack indexed shards while preserving inherited
overlays and exact precedence, or reject that candidate. No production gate can
silently treat inspector acceptance as deployment acceptance.

Reserve decoded bytes before allocation and account for objects pinned by in-flight
queries even after their LRU entries are evicted. A cache hit shares the same backing
buffer charge; repeated references must not manufacture either extra capacity or
double charges. Release transient and query pins on success, failure and cancellation.
Bound relationship/ASN row materialization and serialized answers before creating
large JS arrays; an answer-byte check only after `JSON.stringify` is insufficient.

Worst-case accounting must additionally include compressed response chunks and their
contiguous copies, native hashing copies, the <=8 MiB decoder window, temporary
decoder blocks, IndexedDB serialization, JS table/view/object overhead, the answer
and its structured clone, and the module/runtime baseline. The 32/96/8 MiB sublimits
provide technical admission bounds; they are not a measurement proving whole-worker
RSS stays below 384 MiB. Actual stable-Chrome peak memory at the accepted worst-case
profile remains an unverified blocking gate until measured. No limit is raised to
make a failing measurement pass.

No whole-dataset benchmark, deployed-page metric, process-memory high-water proof or
hosted browser test has been measured by these contract amendments.

## Synthetic diagnostic harness

`tools/hosted/performance.mjs` records twenty independent cold mobile hero contexts,
five cold synthetic overview lookups and sixty trusted graph event-to-paint samples.
Mobile uses the CPU/network model above; desktop graph measurements use native CPU.
It additionally records raw animation-frame intervals during ten seconds each of
trusted keyboard pan, wheel zoom and route-focus changes. The report retains
one-second frame counts, distributions, the actual visible node count, exact static
candidate/release hashes and configuration/fixture/toolchain input hashes. Missing
candidate or contract-input provenance fails measurement before launching Chrome.
The candidate must be compiled with `atlas synthetic -graph24`. This opt-in release
adds the artificial `AS424240` query: twelve observed sequence routes form exactly
24 unique nodes and 23 observed adjacencies, with three exits from the shared second
hop and no clipping. The original `Synthetic()` golden release remains unchanged.
A separate Go-produced compressed fixture binds both readers and the browser graph
projection; it does not qualify any real ASN, source or path coverage.

The graph measurement requires exactly 24 visible nodes and all twelve routes.
Each of keyboard pan, wheel zoom and trusted route-focus changes runs for at least
ten seconds. Report every complete one-second frame count; a measured count below
50 fails the unchanged gate. Missing population/action/interval evidence remains
unmeasured. The harness verifies that route focus never changes node positions.
Event-to-paint latency has no separate invented threshold.

For an immutable HTTPS deployment-hash Pages URL, the same harness writes
`reports/performance-preview.json` with `scope: hosted-synthetic-measurements`
and records the actual Pages response transport. Mutable branch aliases,
credentials and other remote origins are rejected. This is one synthetic desktop
graph context, not the complete required theme/viewport population. Full interaction
INP/CLS, peak browser memory, full dataset capacity and that population remain
explicitly unmeasured; `hosted_gate_passed` and overall acceptance remain false.
The preview workflow verifies the frozen candidate before and after these checks.

The local Python static server sends uncompressed JavaScript. LCP therefore measures
that exact local transport, not Cloudflare Pages compression or a hosted page. The
initial-JavaScript metric separately computes each observed JavaScript response's
gzip-level-9 size as specified above. An over-budget local LCP is retained as a
failure against the unchanged target; transport context does not convert it into a
passing hosted result. Missing/full-population metrics stay explicitly unmeasured.

Any measured `over_limit` comparison or measurement error exits nonzero. The report
separately identifies failed and unmeasured local comparisons. Its
`local_absolute_gates_passed` flag remains false while any listed comparison is
unmeasured; `measured_local_comparisons_passed` covers only the measured subset.
`hosted_gate_passed` remains false for every local run. A completed diagnostic with
pending measurements cannot be used as production acceptance.

## Local measurement checkpoint: 2026-11-08

The exact synthetic candidate
`0ba0cea29db0d8a0494eb19dfc8ea17060576c1584b62dcb822a6020889bcb4f`
was measured in Chrome 156.0.8078.80 on Windows x64 using Node 26.13.0. The host is
an i9-13900H with 14 logical CPUs and approximately 31.6 GiB RAM, not the standard
hosted runner. Raw samples, eight input hashes and the immutable release identity
are in the private `reports/performance-local.json`.

| Diagnostic | Samples | p50 | p95 | p99 |
|---|---:|---:|---:|---:|
| Cold mobile hero LCP | 20 | 2100 ms | 2268 ms | 2320 ms |
| Cold hero CLS | 20 | 0 | 0 | 0 |
| Observed initial JavaScript, gzip level 9 | 20 | 192214 B | 192214 B | 192214 B |
| Cold synthetic atlas response bodies | 5 | 10071 B | 10071 B | 10071 B |
| Three-node graph capture-to-paint opportunity | 60 | 5.0 ms | 9.3 ms | 15.4 ms |

The hero made zero atlas requests. The graph additionally records ten seconds each
of active pan, zoom and route focus, with raw frame intervals. Its three nodes do
not certify the required 24-node graph. Full interaction CLS/INP, browser allocation
and peak RSS, complete viewport/theme populations, full-source capacity, hosted
runner budgets and Pages acceptance remain unmeasured.

Earlier uncompressed-transport LCP p95 failures are retained: 5024 ms before the
SSR-visible hero repair, 4236 ms after it, and 2528 ms after Nuxt UI component
detection. Waterfall inspection found the render-blocking stylesheet competing
with eager JavaScript downloads. Generating only the twelve used component themes
reduced that stylesheet from 205352 to 71481 bytes; limiting generated semantic
variants to the used primary/error palette reduced it to 58718 bytes. These are
source changes; the CPU/network model and thresholds were unchanged. The final
2268 ms result uses the same uncompressed local server.

`measured_local_comparisons_passed` is true for this measured subset.
`local_absolute_gates_passed` and `hosted_gate_passed` remain false. This checkpoint
does not replace the failing/unverified Go lookup and full-capacity gates recorded
in the validation report.
