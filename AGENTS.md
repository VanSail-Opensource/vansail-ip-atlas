# AGENTS.md — VanSail IP Atlas Engineering Standard (v3)

This is the **normative** engineering contract for all changes in this repository. The implementation plan explains why; this file specifies what agents and contributors **MUST** do. When conflicts exist, prefer data correctness, no secret leakage, deterministic static deployment, and this v3 specification over older designs.

## 1. Mission, scope, architecture

- Build **VanSail IP Atlas**: Go data compiler, custom compressed read-only VIA3 files, Nuxt 4 static site on Cloudflare Pages.
- All enrichment is via downloaded bulk datasets. No live IP lookup API, server runtime, Pages Function, network scan, proxy connectivity validation, proxy execution, or DNS resolution of subscription hosts.
- Every IP lookup must be indexed: adaptive radix O(1) bounded depth or O(log n); ASN index O(1) expected or O(log n). Sorting and external merge during offline compilation may be O(n log n).
- Target standard private Actions: 2 vCPU, 8 GiB RAM, 14 GiB disk. Protect RSS and scratch budgets; stream expensive inputs.
- Source metadata must be retained in build-private audit/lineage only. **Never publish source names, source URLs, source IDs, per-source records, collector identifiers, or source attributions in binary database files or frontend bundles.** License and data-rights checks remain mandatory internally; decline to include sources that cannot satisfy this public-output contract.

## 2. Required reading and change protocol

Read `IMPLEMENTATION_PLAN.md`, `configs/sources.yaml`, `configs/scoring.yaml`, `configs/tier1.yaml`, `configs/web.yaml`, and the file format spec before writing code. For every change, identify affected source schemas, binary files, public fields, routes, performance budgets and tests. Add a minimal fixture for every bug. Write a focused regression first where practical. Never make silent semantic changes to risk weights, T1 thresholds or prefix treatment.

After coding, report modified paths, hosted regression results, benchmarks and any unverified assumptions. Do not claim a CI test passed unless it actually ran. Never describe a candidate source as verified from its repository description alone.

## 3. Go implementation rules

- Use current supported stable Go; standard library first. Use `net/netip` for all IP representations and `net/netip.Prefix` for prefixes. Normalize IPv4-mapped addresses and reject malformed/special addresses where the source requires public IPs.
- No global mutable build state. No arbitrary `map[string]any` after parsing. Use versioned tagged record unions and field-specific merge functions.
- Source adapters: streaming reader → typed normalized record → bounded partition sink. Source YAML controls parser, URL, fields, timestamp/freshness, correlation family and approval.
- Use deterministic ordering and little-endian stable binary layout. Do not serialize Go pointers or runtime-specific `unsafe` structs.
- Handle context cancellation, decompression bombs, archive traversal, invalid UTF-8, large lines, request redirects to private networks, HTTP rate limits, bounded retries, atomic writes and partial files.
- All benchmarks include p50/p95/p99, RSS, temporary disk, allocation count and input size. Use bounded channels, adaptive concurrency and external sorting for large BGP sets.

## 4. Source handling and freshness

- Normalize URLs and hashes, deduplicate exact snapshots, then original publishers and derivation families. Aggregators must never manufacture independent evidence votes.
- `max_age=720h` measured against a verifiable upstream content-published timestamp. An HTTP `304`, newly downloaded old blob or new local mirror timestamp does **not** reset age. If freshness cannot be established, quarantine the source until reviewed.
- Exclude stale sources from current compilation, **recompute dirty partitions from surviving sources**, delete expired internal snapshots and output blocks, and prune removed blobs after bounded rollback retention.
- A source is enabled only after downloadable file validation, observed schema fixture, freshness proof, redistribution/data-rights review and a successful parser test. Public source credits are prohibited: if a source requires such credit, that source cannot be published in this product.
- Never emit fields from the public denylist: `timezone`, `postal`, `continent`, `collector`, `latency`, `protocol`, `port`, `hostname`, `domain`, `source_id`, `source_name`, `source_url`, credentials, subscription URI, per-source provenance.
- Permitted public facts include country, region, city, coordinates, ASN/network, usage type, quality and reason flags, native/broadcast mode, BGP routes/relationships/T1 candidates, RPKI and `/24` profile. Unknowns stay unknown.

## 5. Subscription decoder security

- The 21 subscription repositories belong to the `proxy_subscription_ip` family. Parse their TXT, Base64, Mihomo YAML or sing-box JSON inputs **only** for literal server IPs, using VLESS/VMess/Trojan/SS/SSR/HY/HY2/TUIC/AnyTLS decoders as syntax parsers.
- Strip credentials, ports, URIs, transport fields, labels, SNI and comments immediately; do not store them in compiled data, logs, fixtures used in public artifacts, or caches outside controlled build-local quarantine.
- Accept only `netip.ParseAddr` success on a literal public IP. Never DNS-resolve domain hosts; never infer actual egress address from server host. Never recursively fetch links embedded in subscriptions.
- Bound input size, encoded line length, nested Base64 depth, YAML anchors, JSON object size and extracted unique IP count. Never execute downloaded bytes.
- Emit IP + `proxy` reason + timestamp + private evidence-family ID; mark Cloudflare ProxyIP as proxy. De-duplicate correlated lists before scoring.
- Regression fixtures MUST cover bracketed IPv6, `vmess` JSON/base64, `ss` userinfo/base64, URI line lists, malformed ports, non-IP hosts, special/private IPs, suspicious credentials, malformed YAML/JSON, extremely large payloads and repeated duplicates.

## 6. Scoring invariants

- Implement `configs/scoring.yaml` **exactly**, with tests for the formulas and coefficients. Treat malware/C2/botnet/abuse as stronger adverse evidence; Tor, VPN, proxy and datacenter contribute smaller configurable evidence and are not equivalent to criminal activity.
- Internally retain evidence-family and age; the public output contains only score, confidence band, reason flags and four layer contributions. No source strings or raw evidence.
- Build separate exact-IP, explicit-CIDR, ASN-wide, and leave-one-out `/24` layers. Never propagate one exact malicious IP across the entire subnet or ASN; ASN risk is a capped contextual influence only.
- Never infer clean from an unlisted IP. If insufficient assessment coverage, return `quality=null`, but still expose any positive reason flags.
- Scores must be finite 0–100, deterministic, monotonic with added independent risk evidence, duplicate-family idempotent, and stable under source ordering. Protect residential/mobile against biased ASN/subnet contamination.
- Use `usage_type` enum residential/business/mobile/datacenter/hosting/education/government/unknown. Assignment mode native/broadcast_or_routed/unknown is independent from anycast and IPv4 directed-broadcast technical flags.

## 7. BGP and Tier-1 invariants

- BGP origin and RPKI are prefix/ASN facts. Preserve multi-origin announcements and validate each origin independently.
- An AS_PATH adjacency is an observation, not definitive provider/peer business classification. Use directed CAIDA-style relationship data and return `unknown` on missing/conflicting relations.
- The graph can distinguish `transit_upstream`, `peer`, `customer`, `sibling`, `unknown`. Provider/customer direction must pass reverse-path fixtures. Peer is never the fallback label.
- Tier-1 membership is **source-derived each snapshot**: relationship core connectivity + provider-free status + customer cone + independent path visibility. Never hardcode ASN memberships or replace missing inputs with an allowlist.
- Graph visualization MUST preserve actual observed hop semantics. Do not invent links, discard uncollapsed original route structure, or present inferred edges as observed forwarding paths.
- Browser graph is bounded at 24 nodes, 2 protected hops and max 3 backbone exits per second-hop ASN. Merged SVG trunks must not connect unrelated gaps.

## 8. Binary format and public schema

- VIA3 must be explicitly versioned; header + section offsets + checksums + compressed payload. A changed schema requires version bump, Go/TS golden fixtures, parser parity and migration test.
- Store independent compressed shards for geo, usage, quality, `/24`, ASN, BGP, and coordinates; dictionary-code common values. Use inherited prefix overlays to preserve LPM across shard boundaries.
- No publicly available source/provenance section. No timezone, postal, continent, collector, latency, protocol, domain, credentials or proxy URI anywhere in public files.
- Ensure Go and browser readers have byte-for-byte equivalent canonical lookup answers. Verify every output shard hash before updating a release manifest.
- Reader must validate length, offsets, checksum, decompression bounds and unknown version before allocation. The browser supports latest stable Chrome only; do not add polyfills or alternate old-browser logic.

## 9. Nuxt/web design standard

- Framework: Nuxt 4 static `nuxt generate`; Nuxt UI primary; shadcn-vue only for distinct missing primitives; one shared token/theme system; Motion for Vue (`motion-v/nuxt`); lazy TresJS hero decoration only.
- **Aesthetic:** minimal words, generous whitespace, layered liquid glass, thin **edge lighting** (masked gradient + focus accent), light/dark modes, accessible contrast. Prefer deliberate transitions rather than decorative infinite loops.
- `/` MUST redirect with HTTP 302 to `/ip`. `/ip` is a centered hero with exactly one IP/ASN input. Current subviews are under `/ip/*`: `/ip/overview`, `/ip/quality`, `/ip/class-c`, `/ip/bgp`, `/ip/asn`. Reserve `/latency`, `/dns-leak`, `/webrtc`, `/cloudflare`, `/split` without implementation.
- **No duplicate information displays.** Single canonical home for each view: geo/map in overview, score and reasons in quality, 256-cell grid in class-c, ASN risks in ASN, BGP graph in BGP. Other pages link instead of repeating a chart/card.
- No source names, "powered by", "inspired by", dataset lists, collector badges or reference project credits shown as IP data. Mandatory OpenStreetMap tile attribution is an independent map condition.
- OSM coordinates map: lazy Leaflet in overview only. Avoid timezone/postal/continent fields. Do not reveal false precision from city centroid coordinates.
- BGP SVG: pan/pinch/wheel/fit/keyboard/path-focus. Select routes without reconstructing graph layout. GPU/3D is not an excuse to obscure real network semantics.
- No runtime API/remote data origin except map tiles. No source metadata is embedded in JS. Keep dark/light color and state parity, reduced-motion, mobile 320/390 and desktop 1280/1440 views.

## 10. Cloudflare Pages deploy rules

- The compiled `_atlas` data directory **MUST** be copied into `web/.output/public` before Direct Upload. No R2/API/network fallback for DB lookup.
- Validate file budget (<18,500 total) and max individual asset (<24 MiB). Do not split into so many shards that deployment fails. All chunks and manifest refer to the same immutable release.
- `_redirects`: `/ /ip 302`. `_headers`: immutable hash-object caching; short-lived release pointer; secure CSP that permits only necessary OSM tiles.
- Create a Pages preview deployment and run **hosted tests on the preview URL** before production. Verify no 404 for any manifest chunk and no external IP enrichment requests.
- Keep rollback-safe last successful deployment until new release verified. Prune aged/inactive data from subsequent deploy trees; no stale records in the current release.

## 11. Mandatory hosted regression and quality gates

Every material PR MUST run:

1. `go test ./...`, selected race tests, decoder fuzz smoke, source-schema fixtures and deterministic binary golden tests.
2. Score invariants: independent evidence monotonicity, family dedupe, bounded ASN contextual risk, `/24` leave-one-out, inadequate coverage, regional/usage-type bias sentinels.
3. BGP invariants: MOAS, origin-specific RPKI, reversed provider/customer perspective, peer/unknown distinction, Tier-1 derivation and missing-source unknown behavior.
4. Go/TypeScript lookup parity for IPv4, IPv6, exact records, inherited prefixes, corruption and invalid versions.
5. Hosted Playwright current-stable Chrome on Cloudflare Pages preview: hero and all `/ip/*` routes, root redirect, light/dark, EdgeGlow, OSM map, score reason chips, Class C keyboard cells, BGP pan/fit/focus, URL deep links, narrow viewports, no duplicate canonical facts.
6. Hosted performance: RSS and scratch budget, incremental full/changed/no-change runtime, hot/cold lookup p95, initial JS/payload sizes, LCP, INP, CLS, graph responsiveness; compare with versioned baseline after enough samples.
7. Public output scanner: source IDs/URLs, credentials, domains, protocols/ports, collector/latency/timezone/postal/continent fields forbidden. Zero stale database entries. Manifest content hashes and full static asset inclusion required.

No automatic release when any mandatory gate fails. Report the gate, sample, and measured failure; do not replace a failing threshold with a larger one without explaining the regression and obtaining review.

## 12. Completion checklist

- [ ] Correct owner route and no duplicate display
- [ ] No forbidden public fields or source references
- [ ] New source has verifiable publication age and reviewed rights
- [ ] Any withdrawn/stale source retracts prior influence
- [ ] No decoded non-IP hostname or credential survives
- [ ] Score/ASN/`/24` invariants and deterministic output verified
- [ ] BGP and Tier-1 classifications not invented
- [ ] Go/TypeScript decoder parity and full binary integrity verified
- [ ] Runner and Pages budgets measured
- [ ] Hosted Chromium regression, performance and quality reports attached
- [ ] Entire immutable dataset included in Pages preview and production deploy
