# Local implementation checkpoint — 2026-11-08

The synthetic stack is implemented and undergoing hosted regression in the public `VanSail-Opensource/vansail-ip-atlas` repository. **The full P0–P7 plan and production release are not complete.** Source captures stay local and ignored; only engineering fixtures enter Git. Dated hosted delivery evidence is recorded in `VALIDATION_REPORT.md`.

## Current implementation pass

The user removed the mandatory complete-risk-feed release prerequisite and then
requested dataset credits. Current `release-scope-v3` keeps numeric quality optional;
insufficient assessment still yields `quality=null` and retains positive reasons.
Existing scoring qualification, weights and thresholds are unchanged. Every
remaining required capability still needs current approved real-source evidence.

Reviewed attribution is now permitted in one lazy-loaded global footer display.
Credit text/links are bound to private source receipts and a content-addressed
public credit document; source IDs and per-IP provenance remain prohibited.
Synthetic releases have no real dataset credits. The updated local compiler,
packager and 19 browser scenarios pass, including shared credits without query
parameters or external requests. Required source fixtures remain unqualified.

- Added `atlas compile-state`, connecting all nine normalized record kinds to deterministic engineering materialization: quality regions, ASN context and direct identity, sparse `/24`, origin-specific RPKI, retained paths and directed relationships. It binds the exact intake/config/certification clock and receipts at publication, rechecks withdrawal and expiry, and refuses production mode. Full bulk streaming, real-source certification and provenance-qualified Tier-1 history remain required.
- Fixed exact-announcement RPKI lookup in both Go and the browser. An unrelated more-specific RPKI row cannot hide the selected announcement's own result. Twelve shared compressed IPv4/IPv6, inherited-overlay and MOAS cases cover this behavior without changing the wire schema.
- Reduced full canonical synthetic Go lookup from about 19.8 to 4.9–6.0 microseconds and from 175 to 39 allocations per operation on this Windows host. This includes shard-owned index metadata, direct query-pinned references and fresh answer-owned scalar storage. Mutable answers stay independent, query pins clear on every exit and no query history is cached. The two-microsecond target remains failing. The conservative size proof retains exact serialization as a fallback; answer-size acceptance is unchanged.
- Added bounded single-stream XZ and ZIP64 ingestion primitives, with dictionary/index/decoded ceilings, per-block integrity and exact consumption, actual ZIP directory-count preflight, and parser-differential end-record rejection. Format support does not certify or enable any real source.
- Added main-push integration and frozen-artifact Pages preview verification. Source-rich reports and captures are excluded from public artifacts. Neither a passing synthetic run nor a checked-in policy flag can authorize production.
- Added exact-file GitHub commit publication proof: a path/ref/repository-bound one-result metadata query and a separately downloaded immutable commit copy must match the original payload's SHA-256 and size. The older author/committer clock and retained earliest-content clock prevent observed identical-byte recommits from renewing age. Tests reject mismatched paths/refs/content, ambiguous JSON, future clocks and stale original content. This implements a proof mechanism without certifying any source.
- Fixed global-credit URL parser parity for legacy numeric IP aliases and nonliteral HTTPS port spellings using shared Go/Python/browser regressions. The graph panel replaces its measured slow backdrop blur with a static theme surface; masked edge lighting remains. Updated hosted acceptance is required separately from the passing causal diagnostic.

## Implemented work

| Area | Executable work |
|---|---|
| Contracts | Closed schemas for all five configs; duplicate/unknown YAML rejection; canonical IP/ASN/URL corpus; byte layouts for all 14 VIA3 kinds; scoring and Tier-1 reference vectors. |
| Admission | Source/coverage/family/rights/fixture checks, empty reviewed adapter-certification ledger, payload-bound clock contracts, dependency withdrawal and a derived private capability report. Labels and reconnaissance cannot activate a parser. |
| Acquisition | HTTPS/public-address pinned dialing, redirect/retry/concurrency/run-byte limits, private atomic files, bounded streaming archive inspection and literal-IP subscription syntax decoders. |
| Intelligence | Config-driven four-layer scoring; inadequate-coverage null scores; family dedupe; MOAS/ASN and leave-one-out `/24`; field-specific geo fusion; coordinates from the winning city; usage conflict handling. |
| Routing | Directed relationships, origin-specific VRP validation, bounded streamed MRT TABLE_DUMP_V2, retained path segments, deterministic Tier-1 primitives and graph selection. |
| Private state | Versioned typed normalized unions, parser/schema/policy-bound receipts, no-change expiry checks, withdrawal/dependency retraction and atomic bounded private state. Initial reconciliation rebuilds all dependent facts on change. |
| Source intake | Closed-config validation before acquisition, exact fixture/ledger/code binding, bounded VRP dispatch, MRT fixture/runtime gate, exact GitHub asset digest/URL/size/time verification, private hash-only anti-replay publication receipts, exclusive writer lock and verified quarantine cleanup. Unsupported combinations stay quarantined. |
| Binary | Deterministic compressed synthetic release, typed partition-compiler work, indexed IPv4/IPv6/ASN readers, inherited overlays, sparse cells, bounded prefix paging, shared Go/TypeScript compressed and hostile fixtures. |
| Offline planner | Disk-backed external sort/merge, deterministic family-free fact identities, actual-byte prefix/ASN repacking with inherited overlays, bounded router metadata, per-partition object emission, resource watchdog and atomic private candidate publication. Geo/Usage/Origins boundary materialization rejects unsupported kinds. |
| Browser | Nuxt static hero plus overview/quality/class-c/bgp/asn; worker lookup; hash validation; bounded IndexedDB/LRU; pinned sessions and expiry; light/dark, reduced motion, OSM, keyboard grid and SVG pan/zoom/fit/focus/export. |
| Packaging | Complete same-origin atlas copy, object and decoded-string checks, source disclosure scanner, strict Pages inventory, canonical manifests, exact approval checks, CSP hashes, software notices and prepared integration workflows. |

The source schema now separates raw fields from public field mappings. Scope and relationship aliases were explicitly normalized, assignment is `assignment_mode`, and internal signals map to public reason bits. Existing risk coefficients, half-lives, four layer weights and existing Tier-1 thresholds were preserved. New deterministic definitions and stability/bootstrap rules are explicit in the owning contract revisions.

The public output schema has no source/provenance section. This work freezes previously unimplemented schema-3 record layouts; it does not migrate an existing production release. Unknown/old versions are rejected and shared corruption fixtures exercise both readers.

## Approved decoder amendment

Installed branded Chrome 156.0.8078.80 rejected native `DecompressionStream('zstd')` for every tested frame. The user explicitly approved a pinned bundled decoder. `fzstd@0.1.1` is the sole browser implementation, with frame/window/content-size checks before allocation, hard output bounds and independent frame checksums. The VIA3 Zstandard codec remains unchanged; there is no remote dependency, alternate codec or native fallback.

The native failure is preserved in `reports/codec.json`; actual bundled Chrome results are in `reports/codec-bundled.json`. Technical public-deployment limits are stricter than generic format-inspection ceilings. They reject oversized working sets instead of truncating facts; the whole-process browser memory requirement still needs measurement.

## Verified evidence and practical limits

Current command results and local artifact measurements are recorded in `VALIDATION_REPORT.md` and private `reports/`. Run the commands in the root README to reproduce them. Source-rich capability reports, normalized state and capture fixtures are never copied into the frontend tree.

Local browser regression covers the root HTTP 302, one hero input, a JavaScript-disabled visible hero, local query rejection, canonical view ownership, deep links/MOAS origin errors, IPv6 Class C state, keyboard cells, graph route selection and standalone SVG download, corrupted worker data, a cancelled earlier query, light/dark and 320/390/1280/1440 widths. Reports bind the exact prepared candidate and verify every served atlas object's hash. Tile requests are stubbed in the automated UI/performance harness; it verifies the renderer, required attribution and network/referrer policy, not live tile availability. These are local Chrome checks, not Cloudflare Pages preview acceptance.

Local lookup/reconciliation benchmarks use tiny versioned synthetic inputs on a Windows i9 host. They do not establish full-dataset capacity. Full canonical Go lookup samples exceed the documented 2-microsecond target; a faster isolated index probe is not substituted for that result. No threshold was raised. Windows race tests cannot start without CGO; Linux race tests passed in the initial hosted integration run.

The final local mobile measurement has LCP p95 2268 ms across 20 cold samples,
192214 gzip bytes of initial JavaScript and zero hero-navigation CLS. The final
candidate and full local evidence are recorded in `VALIDATION_REPORT.md`.
Measured local comparisons pass; the overall and hosted performance flags stay
false because the 24-node graph, full interaction and memory populations remain
unmeasured. All three earlier LCP failures are retained with their original results.

## Blocking work still required

1. **Real-source certification:** 91 sources remain at 82 candidate, seven rights-approved and two retired; zero active, zero fixture-tested and no complete risk-coverage family. Numeric quality is optional/unrated under `release-scope-v3`; the other 12 required capability rows remain blocked. Redistribution and required-credit compliance, exact payload publication proof and observed parser certification still need source-specific evidence. Subscription items without a verified upstream item clock are quarantined.
2. **Complete production ingestion and materialization:** the external planner and bounded reviewed intake now exist, and `compile-state` materializes all nine normalized kinds, including explicit ASN identity. Full real-adapter discovery/proof coverage, streamed private state and qualified Tier-1 history remain unfinished. The mapper preserves constant quality regions rather than propagating exact risk from an ancestor's first address. Intake still caps each source at 100,000 rows/64 MiB and complete normalized state at 64 MiB. The privately observed 125,830-row ASN CSV exceeds that input cap; parser support does not qualify full intake. The new materializer has an explicit bounded engineering population; it is not full bulk ingestion. Cache blob retention/GC, changed-partition reuse and full recompilation require actual-source capacity evidence.
3. **Format/parser scope:** XZ/ZIP64 now have bounded synthetic integrity/security coverage, but real adapters still need individual schema/freshness/rights certification. TABLE_DUMP_V2 IPv4/IPv6 unicast/ADDPATH and the separate BGP4MP event parser are engineering components; live update feeds still require a disk-backed session/withdrawal replay reducer. Tier-1 history eligibility must be supplied from revalidated source receipts; a primitive or event parser does not certify a historical snapshot.
4. **Full mandatory quality/performance:** broaden the shared corpus and actual-browser failure/cache/late-query checks, qualify all schemas, measure process-group RSS and scratch, cold/changed/no-change builds, full lookup distributions, 24-node graph performance, real accessibility/INP and the standard hosted baseline. Investigate failed measurements; never enlarge gates to force a pass.
5. **Distribution review:** direct software notices are independent of IP-data provenance. Actual client/worker module ancestry now proves the 25 missing installed-package notices are absent from the Windows browser product; all 60 observed packages have copied notices. Each hosted build independently verifies its exact emitted code tree and fails if an unresolved runtime notice appears. The installed-package gaps remain recorded; no notice or grant was invented.
6. **P7:** complete real immutable release, current capability evidence, hosted Pages preview with full object availability and privacy/route/header checks, exact artifact/hash approval, protected production promotion, live post-deploy verification and an eligible rollback artifact. Approval remains false and packaging refuses production mode.

The remaining source qualification problem cannot be repaired by synthetic fixtures, treating positive-only absence as clean or using a Tier-1 allowlist. Production stays unavailable until the user-approved scope is supported and all required gates actually run.
