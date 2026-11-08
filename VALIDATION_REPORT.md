# VanSail IP Atlas - Implementation validation (2026-11-08)

The local synthetic compiler and static application are runnable. **The full P0-P7 production plan remains incomplete.** Real-source qualification, full bulk ingestion, mandatory capacity/performance gates and production deployment remain blocked. The public implementation repository is `VanSail-Opensource/vansail-ip-atlas`; delivery evidence is recorded as it actually runs, independently of local results below.

Run instructions are in [README.md](README.md); exact implementation boundaries are in [docs/implementation-status.md](docs/implementation-status.md). The earlier capture-only report is preserved in [docs/history/source-capture-validation-2026-11-08.md](docs/history/source-capture-validation-2026-11-08.md) and does not describe the current code.

## Subsequent implementation and local verification

The current pass adds the same-clock `compile-state` materializer, bounded XZ
and ZIP64 ingestion primitives, exact-announcement Go/TypeScript RPKI parity,
lookup allocation/answer-size improvements, and BGP4MP/AS4 replay-event parsing.
The materializer supports the eight existing normalized record kinds while
remaining an engineering population; real bulk state, ASN labels, Tier-1 history
and transactional update replay remain unfinished. No source was promoted and
no score coefficient, Tier-1 threshold or public wire schema was changed.

Local `go test ./...`, `go vet ./...`, TypeScript checking, 78 Python contract
tests and four frozen-candidate regressions passed. The expanded shared Node
VIA3 suite has 41 passing cases, including 12 selected-announcement RPKI cases.
BGP4MP fuzz smoke passed 287,312 executions in five seconds. Independent archive
review covered XZ CRC variants, cancellation, corrupt block checks, forged
indexes, ZIP actual-directory allocation bounds and ambiguous end records.

Full canonical synthetic Go lookup is now approximately 9.5–10 microseconds,
2,215 bytes and 74 allocations per operation on the same Windows host, with
about 23.6 MB process peak RSS and no lookup scratch. It still fails the unchanged
two-microsecond target; these are not hosted or full-dataset results. Private
logs are `reports/lookup-after*.log`.

Public Git and CI artifacts exclude upstream captures, normalized private state
and source-rich reports. Copied third-party notice bytes retain their original
whitespace and hashes. The local private sample-inventory integration test skips
explicitly when captures are absent on a public checkout; this is not a real
source-schema certification pass.

## Modified areas and contract impact

| Paths | Implemented behavior and affected contracts |
|---|---|
| `configs/`, `schemas/`, `docs/`, `tools/atlas_contracts/` | Closed config schemas, source controls, scoring/Tier-1 definitions, browser parsing, explicit VIA3 record layouts and default-deny approval. Existing risk coefficients and Tier-1 thresholds are preserved. |
| `internal/acquire/`, `internal/admission/` | Pinned public-address HTTPS dialing, bounded downloads/archives, narrowly scoped signed GitHub asset redirect, reviewed fixture/code binding, exact asset publication proof, earliest-content clocks and exclusive private intake lifecycle. Runtime MRT stays quarantined pending its dedicated coordinator. |
| `internal/subscription/` | Literal-public-IP-only syntax decoders; credentials, transport and non-IP hosts do not survive normalization. Unknown item publication clocks cannot inherit a wrapper's date. |
| `internal/intelligence/`, `internal/facts/` | Four-layer scoring, family/age handling, geo/usage fusion, directed BGP relationships, MOAS/RPKI, Tier-1 primitives and typed reconciliation. Exact-payload-connected families correlate transitively; withdrawal recomputes that grouping. |
| `internal/via3/`, `internal/pipeline/`, `cmd/atlas/` | All 14 shard layouts/readers, typed partition compiler, disk-backed sort/merge/repack, original-prefix overlays, bounded indexed router, atomic private candidates, mapping-only materialization and local commands. Inspector and facts input reject nonregular files before opening. |
| `web/app/`, `web/nuxt.config.ts`, frontend lockfiles | Static hero and all five canonical `/ip/*` views, worker integrity/cache/expiry, themes, lazy map and bounded graph. Graph clipping preserves protected hops and original structure; downloaded SVG includes standalone paint/text styles. Unused UI component/color variants are removed. |
| `fixtures/contracts/`, `fixtures/bin/`, scoring/BGP fixtures | Synthetic shared syntax/formula/binary/corruption and graph regressions. They do not certify a real source. Raw reconnaissance captures were not promoted into production fixtures. |
| `tools/release_contract/`, `tools/hosted/`, `.github/workflows/` | Complete same-origin asset packaging, disclosure/integrity scanner, operational timestamp normalization, exact approval identity checks, source-free reports, browser/performance harness and draft integration workflow with no release job. |

Public fact fields and VIA3 wire codec remain schema 3/Zstandard. This is the initial byte-level freeze of a previously unimplemented schema; old/unknown versions fail closed. Source names, URLs, IDs and per-source provenance have no public fact representation. Public software notices and required OSM tile attribution are independent of IP-data attribution.

The user explicitly approved the pinned bounded bundled decoder after actual Chrome rejected native Zstandard. `fzstd@0.1.1` is the sole implementation; no remote decoder, alternate codec or old-browser polyfill was added.

## Exact prepared artifact

| Property | Verified local value |
|---|---|
| Mode | Synthetic engineering preview |
| Public tree | `web/.output/public`, including complete `_atlas/` |
| Candidate tree SHA-256 | `0ba0cea29db0d8a0494eb19dfc8ea17060576c1584b62dcb822a6020889bcb4f` |
| Dataset release ID | `90015b0b0e3109ac863619fbb3ff9375caa150a237ced364ec2f7dfea2054e9b` |
| Objects / physical files | 17 / 84 |
| Physical tree bytes | 2,139,603 |
| Largest asset | 1,164,912 bytes (`licenses/software.txt`) |
| Explicit synthetic evaluation clock | 1794096000 UTC Unix seconds |
| Aggregate synthetic validity bound | 1796688000 UTC Unix seconds |

Two complete `nuxt generate` calls followed by preparation produced identical full-tree digests. Only known framework operational timestamps are canonicalized to the release clock; no source/item publication clock, data byte or expiry decision is renewed. All object hashes, decoded dictionaries, public output and inventory limits passed. The final HTTP regression also fetched every declared object and verified its byte count/hash. These are local synthetic checks, not Pages acceptance.

Evidence: `reports/static-candidate.json`, `reports/reproducibility.json` and `reports/ui-regression.json`. The tree stays below 18,500 files and every asset below 24 MiB. No source-rich report or private state is copied into it.

## Executed local checks

Toolchain: Go 1.27.3 on Windows/amd64; pinned Node 26.13.0, pnpm 12.18.0; actual branded Chrome 156.0.8078.80. Dependency versions are locked in `tools/hosted/toolchains.json` and package/module lockfiles.

| Check | Actual result |
|---|---|
| `go test ./...` and `go vet ./...` | Passed; final command/input guards also passed focused tests after the CLI memory/deadline policy change. |
| Python contract suite | 78 tests passed. |
| Shared Node query/VIA3/codec/graph/performance-gate suite | 185 tests passed. |
| `pnpm typecheck` / `pnpm generate` | Passed; the complete prepared tree reproduced byte for byte. |
| Bundled codec in actual Chrome | 12 cases passed on pinned Node; original native failure retained separately. |
| Browser HTTP/UI/privacy regression | 17 scenarios passed, including JavaScript-disabled hero, five canonical owners, four widths, light/dark, grid keyboard, graph focus, standalone SVG exports, corrupt worker input and cancelled slow query. |
| Source intake | Actual catalog returned 0 current of 91, with no downloads. Repeated same-clock intake reported `FullRebuild=false`; the exclusive engine lock was released. |
| Disk-backed facts command | Three typed synthetic facts compiled into four objects; exact-IP precedence and unknown quality verified by lookup. Production mode is rejected. |
| Race tests | Could not start: `-race requires cgo`; current Windows `CGO_ENABLED=0`. No race pass is claimed. |

Five-second fuzz smoke runs passed: production subscription decoder **142,241** executions, MRT parser **252,736**, VIA3 reader **230,742**, separate reconnaissance decoder **9,318**. Raw logs are under private `reports/`. Linux device/FIFO regressions were added but were not executed on Windows; a Linux test binary cross-compile is not a Linux runtime test.

The browser harness stubs OSM tiles. It checks renderer/attribution and absence of query-bearing referrers or unexpected external origins, not live tile availability. The UI report binds the exact prepared candidate/release. Hosted Chrome, full accessibility and full viewport/theme sample populations remain unverified.

## Local performance and resource evidence

The host is a Windows i9-13900H machine, not the prescribed hosted 2-vCPU/8-GiB/14-GiB runner. Go benchmarks used `GOMAXPROCS=2`; that does not change the physical host or establish full-dataset capacity.

- **Full canonical Go lookup exceeds the 2-microsecond target.** On the 8,379-byte synthetic corpus: 20.774 microseconds/op, 11,663 bytes and 175 allocations/op; batch-mean p50/p95/p99 were 17.559/41.090/53.838 microseconds. Windows short-interval batch means are not a hosted per-query latency distribution. RSS was not measured for this reader benchmark; it uses no compilation scratch. The separate 476.3-nanosecond zero-allocation index probe is not substituted for full lookup acceptance.
- Disk-backed compile: 256 synthetic records / 90,661 input bytes / 12 measured invocations; p50 168.1804 ms, p95/p99 193.6381 ms; 63,305,373 allocated bytes and 222,502 allocations/op. Compiler-process RSS high-water 23,109,632 bytes; owned scratch high-water 182,856 bytes. This excludes other processes and previous output trees. Raw samples: `reports/pipeline-benchmark.log`.
- Final actual Chrome measurement on the exact candidate: 20 independent cold mobile hero samples; **LCP p50/p95/p99 2100/2268/2320 ms**, within the unchanged 2500-ms target. Hero-navigation CLS was 0; initial JavaScript was **192,214 gzip bytes** (limit 204,800); the hero made zero atlas requests. Five cold synthetic lookups each transferred **10,071 atlas-body bytes**, including pointer/manifest/router/dictionaries/shards. The three-node graph had 60 event-to-paint samples (p50/p95/p99 **5/9.3/15.4 ms**) plus 30 seconds of active pan/zoom/focus frame measurements. This is not the required 24-node graph population. `measured_local_comparisons_passed=true`, `local_absolute_gates_passed=false`, `hosted_gate_passed=false`; missing mandatory measurements are not passes. Exact protocol, samples and hashes: `reports/performance-local.json`. Earlier failed LCP p95 values **5024, 4236 and 2528 ms** remain preserved in their separate reports.

The hero's initial SSR opacity bug was fixed with a JavaScript-disabled regression. Nuxt UI component detection removed unused themes, then the unused semantic color aliases were removed. Critical entry CSS fell from 205,352 to 58,718 raw bytes. Measurements use the unchanged throttled mobile network/CPU model and an uncompressed local static server; transport context does not convert a failed comparison into a pass. A measured over-budget comparison now exits nonzero, while missing metrics remain explicitly unmeasured.

## Production blockers and remaining work

1. The catalog has 82 candidates, seven rights-approved entries and two retired entries; **zero active/current and zero real parser fixtures**, with no complete risk-coverage family. All **13/13 production capability rows** remain blocked. All 21 subscription repositories share one evidence family. No rights, attribution permission, source activation or publication proof was invented.
2. Full admitted-source streaming, discovery/proof coverage, risk/BGP/Tier-1/ASN identity materialization, incremental dirty-partition reuse and source/blob retention/GC are unfinished. Mapping materialization deliberately supports only Geo/Usage/Origins and refuses production; input receipt expiry bounds its synthetic release. Intake has a 100,000-row/64-MiB per-source limit and a 64-MiB complete-state ceiling. Exceeding a bound rejects the build instead of truncating facts. Hash-only anti-replay audit retention also needs production policy review alongside no-renewal guarantees.
3. Runtime MRT remains disabled pending the max-two-source, sequential, shared-1-GiB cold-acquisition coordinator. TABLE_DUMP_V2 unicast/ADDPATH parsing exists; BGP4MP and AS4_PATH transition reconstruction are not implemented. XZ/ZIP64 production input is rejected pending a bounded certified decoder. Trusted subscription per-item publication verification is still missing.
4. Full-source schema/freshness/redistribution qualification, whole-process RSS/physical disk high-water, full/changed/no-change runtime, hot/cold lookup populations, 24-node graph performance, field/lab INP, interaction CLS, complete browser memory/allocation accounting and hosted accessibility remain unmeasured. The known Go lookup failure stays blocking.
5. Direct software notices are included. The conservative installed-dependency audit copied 567 package notices and still reports 25 missing packaged notices requiring actual runtime-bundle classification/review. No IP dataset attribution exception was granted.
6. No hosted workflow, Pages preview, production upload or rollback verification ran. The draft workflow uploads source-free status instead of the source-rich capability report; it contains no production token or release job. Exact-hash approval is still false, and static packaging refuses production mode. P7 promotion/rollback remains unfinished.

No production release or full-plan completion is declared by this report.
