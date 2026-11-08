# VanSail IP Atlas v3 - Execution-Ready Implementation Plan

## Status, authority and production gate

Local implementation is now in progress (2026-11-08). The current executable work, user-approved bundled-Zstandard amendment, commands, measured results and remaining integration/production gates are recorded in `docs/implementation-status.md` and `VALIDATION_REPORT.md`. The catalog/reconnaissance snapshot and gap register below describe the starting state; they do not override those dated execution results. No phase or production release is declared complete by this checkpoint.

This document is the implementation plan; it is not a release claim. `AGENTS.md` remains the normative engineering contract. If this plan conflicts with `AGENTS.md`, `AGENTS.md` wins. The documents listed under **Authoritative contracts** define the executable details that this plan schedules and gates.

Workspace review: **2026-11-08**. The source catalog and format-sample inventory have been reconciled after unavailable entries were removed. Observations below were checked against local files; no upstream freshness, rights, parser certification, hosted regression or deployment was revalidated.

The current source-admission snapshot is:

- 91 source entries: 82 `candidate`, 7 `rights_approved`, 2 `retired`, 0 `fixture_tested`, 0 `active`.
- All 91 entries have `fixture.status: missing`.
- Publication proof is `unavailable` for 65 entries. The remaining entries use GitHub release or commit metadata, which still has to be tied to the exact payload and verified at build time.
- No source declares `complete` coverage: 39 declare `mapping` and 52 declare `positive_only`. Numeric quality therefore has no qualifying complete family in the current catalog.
- The seven rights-approved entries have `distribution: allow`, but none records an explicit `attribution_required: false`; explicit no-attribution proof remains required before activation.
- All 21 proxy-subscription repositories use `evidence_family: public-subscription-aggregators`.
- BGP MRT ingestion is disabled, and no required BGP/Tier-1 capability is currently qualified.

The workspace also contains format reconnaissance, which is separate from admission:

- `fixtures/source-samples/manifest.json`, updated on 2026-11-08, covers all 91 entries and matches the current source-catalog SHA-256.
- It records 68 raw fragments, 21 sanitized subscription fragments, and 2 retired entries. No blocked or failed source entries remain in the catalog or current inventory. Captures do not establish present upstream availability.
- These 89 captures are not full-payload schema/parser fixtures. Sanitized fragments may omit the structure needed to exercise the production decoder. Neither capture status nor the capture tool's historical tests promote a source to `fixture_tested` or `active`.
- At the starting snapshot, only the Go module, sample tool, structural validator and static header templates existed. The current compiler, readers, Nuxt application and remaining production integration are recorded in `docs/implementation-status.md`; this historical inventory is not the current implementation status.

Consequences:

1. Production is hard-blocked until every capability in the capability matrix has approved, current, fixture-tested real-source coverage.
2. Rights approval alone does not qualify a source. The seven `rights_approved` entries still lack observed fixtures and explicit no-attribution proof, so they cannot be active.
3. Synthetic fixtures may validate engineering behavior in previews. They must never satisfy a production gate or be described as real coverage.
4. No feature may be silently dropped, replaced by an allowlist, or filled with a placeholder to bypass the block. Production remains unavailable until the promised capability is genuinely supported.

## Product contract

VanSail IP Atlas is a source-free, download-only IP and ASN intelligence site. A Go compiler ingests approved bulk datasets, emits deterministic VIA3 shards, and packages them with a Nuxt 4 static site in one Cloudflare Pages deployment. There is no lookup API, Pages Function, proxy probe, DNS resolution of subscription or query hosts, runtime database, or remote enrichment request.

The v1 product contract covers:

- IPv4 and IPv6 country, region, city and quantized coordinates.
- Network identity and every origin for MOAS prefixes.
- Usage, assignment, anycast and IPv4 directed-broadcast facts when explicitly evidenced.
- Explainable risk reasons, numeric IPv4 quality when coverage is adequate, and unrated states otherwise.
- IPv4 `/24` context, ASN-wide context, RPKI, observed BGP paths, directed relationships and source-derived Tier-1 candidates.

Non-negotiable constraints:

- Standard 2 vCPU / 8 GiB / 14 GiB hosted-runner budget.
- Indexed lookups use O(1) expected or O(log n) bounded-depth operations.
- The complete immutable release is bundled into Pages; there is no R2, API or network fallback.
- Fewer than 18,500 files and less than 24 MiB per asset.
- Freshness is at most 720 hours from a verifiable upstream content-publication clock.
- Public output contains no source name, source ID, source URL, per-source record, credential, proxy URI, domain, protocol, port, collector identity, latency, timezone, postal code or continent.
- Latest stable Chrome only; no polyfills or alternate codec.
- Missing, stale, corrupt or incomplete input fails closed.

## Authoritative contracts and precedence

The following documents are normative and must be implemented together. Listing them here does not mean their contracts are complete:

- `docs/binary-format-via3.md`: VIA3 container layout, reader validation, limits, determinism and golden fixtures.
- `docs/data-model.md`: internal evidence, public presence masks, multi-origin identity, quality states and reason flags.
- `docs/scoring.md`: formulas, coverage semantics, confidence, geolocation and usage fusion.
- `docs/source-policy.md`: admission/runtime states, publication proof, evidence families, rights and capability gating.
- `docs/performance.md`: build, lookup, browser and Pages budgets.
- `docs/release.md`: immutable manifest, approval binding, preview, deployment and rollback.
- `docs/bgp-tier1.md`: deterministic relationship, path, Tier-1 and graph contracts.

`configs/sources.yaml`, `configs/scoring.yaml`, `configs/tier1.yaml`, `configs/web.yaml` and `configs/release-approval.yaml` must validate against typed schemas with unknown fields rejected.

Precedence is:

1. `AGENTS.md` and the non-negotiable constraints above.
2. The public data/source/release contracts and versioned configs, with `configs/scoring.yaml` authoritative for scoring equations and coefficients as required by `AGENTS.md`.
3. Explanatory material, examples and historical validation reports.
4. This plan's delivery order.

An unresolved conflict among normative files blocks the affected implementation. It must be recorded and reconciled during P0; an implementer must not silently choose a formula, enum spelling or fallback. Requirements introduced below describe work to freeze in the owning contracts, not a claim that the current schemas already contain those fields.

Any semantic change to a public field, risk weight, T1 threshold, prefix overlay, freshness rule or source-admission rule requires a contract amendment, a version bump where applicable, and new Go/TypeScript golden coverage before code can land.

## Source admission, freshness and independence

### Static admission

`admission` records a certification milestone; it is not a substitute for evaluating each gate. `fixture_tested` and `rights_approved` are peer milestones, not a linear ladder. A source can be rights-approved while its fixture is still missing, as seven catalog entries currently are. When both milestones pass but activation has not occurred, the label may retain the most recently reviewed milestone; qualification is always derived from the individual fixture, rights, proof and runtime fields, never from the label alone.

- `candidate`: cataloged; must not be fetched for publication, used for scoring or admitted to a release. Bounded build-private reconnaissance and parser certification may inspect candidates without enabling them; their artifacts never enter the production input cache or public tree.
- `fixture_tested`: the parser ran against a pinned observed payload, the expected schema matched and the fixture SHA-256 is recorded. This state alone does not grant use.
- `rights_approved`: the redistribution decision claims that public derived output is permitted. Activation additionally requires an explicit `attribution_required: false`; the field must not be inferred from absence. This state alone does not grant use.
- `active`: every static gate below passes. Only this state is eligible for production ingestion, subject to runtime revalidation.
- `retired`: immediately excluded from current compilation, with all current contributions retracted. Private audit or rollback retention never delays that retraction and is allowed only under the bounded eligibility/rights rules in C07.

An entry may be changed to `active` only when all of the following are true:

1. An exact downloadable asset or deterministic snapshot-discovery rule is defined.
2. Parser and expected schema are recorded.
3. `fixture.status` is a passing state, `schema_observed` is true, the fixture has a valid SHA-256 and the tested fixture identifies the same parser/schema.
4. `publication_proof` is not `unavailable` and is bound to the exact payload.
5. Redistribution is allowed, `attribution_required` is explicitly `false`, and the rights review is recorded.
6. `evidence_family`, `coverage`, `scope`, public-field allowlist and dependencies are explicit.
7. The source is current under the 720-hour clock at fetch time.
8. The admission and runtime state machines accept the transition.

An `active` entry is still rechecked on every build. The static label does not override a runtime `missing`, `stale`, `invalid` or `quarantined` result; an ineligible payload contributes nothing even if the YAML milestone has not changed.

### Runtime state

- `current`: verified fresh payload with matching schema and fixture.
- `stale`: publication age exceeds 720 hours, or a changed publisher asset invalidates the prior proof.
- `missing`: asset cannot be discovered or downloaded within the bounded retry policy.
- `invalid`: schema, hash, archive, parser or safety validation failed.
- `quarantined`: freshness is unknown, proof is untrustworthy, rights are ambiguous or the source must be reviewed.

Only `current` sources contribute records. When a source leaves `current`, delete its eligible internal snapshot, remove all its contributions and rebuild every dependent exact, prefix, ASN, `/24`, routing and graph partition. Build-private audit may retain permitted hashes and decisions, never subscription secrets. A cache hit must never mask withdrawal or staleness. Missing required coverage blocks the new release even when recomputation succeeds.

The 720-hour limit is a ceiling, not an extension of a stricter policy. `build.proxy_subscription.expiry_hours` is currently 168; P0 must freeze its event clock and interaction with source and item publication times. An old item does not become new because its containing snapshot was republished. Every incremental build, including a no-change build, reevaluates time-based expiry and policy/rights withdrawal before declaring a cache hit.

### Publication proof

The accepted clocks are:

- an embedded publisher timestamp in the payload;
- publisher release metadata tied to the exact asset;
- an explicitly allowlisted authoritative header from an allowlisted origin.

The header allowlist is empty initially. Adding one requires a contract change with origin, header, cache/proxy caveat and fixture coverage. GitHub commit proof is accepted only when the downloaded URL is pinned to an immutable commit or the payload blob is proven to belong to that commit. A commit to a repository is not proof for a mutable branch asset.

The following never establish or extend publication age: HTTP fetch time, cache time, local timestamp, mirror modification time, a different asset in the same release, HTTP `304`, repository description, or release title without per-asset binding. A source with no proof is quarantined and its prior contributions are removed. Times more than 24 hours in the future quarantine the source; future times within 24 hours are clamped to zero age. Negative historical age is also clamped to zero.

### Evidence independence

`evidence_family` is the sole scoring-independence key. Mirrors, protocol partitions, multi-file publisher releases and all 21 proxy-subscription repositories count once per signal and applicable scope. `correlation_group` is operational metadata, not an additional vote. The subscription category is `proxy_subscription_ip`; the catalog's shared independence key is `public-subscription-aggregators`. These labels do not create separate voting families. Other aggregators must also be traced to their original families; unresolved dependence cannot manufacture independent votes. Splitting a family requires documented original-source provenance and a reviewed contract change.

### Coverage

- `complete`: absence over the declared scope is an authoritative negative observation.
- `positive_only`: absence is unknown and must never be treated as zero risk.
- `mapping`: complete only for the mapped geographic/network fact, never for reputation or safety.

A parser must not infer coverage from a source's name. Coverage is a reviewed property of the exact observed payload and scope.

## Capability gate

The release tooling must derive this matrix mechanically from the catalog, fixtures, rights decisions and current snapshots. The table is the plan's starting state, not a manually maintained release override. Every row is blocking; one failure blocks production.

| Capability | Required approved current evidence | Snapshot status | Gate |
|---|---|---|---|
| Country | At least one current mapping family | Three country entries are rights-approved but have no fixture | Blocked |
| Region/city | Two independent current mapping families with deterministic fusion | Candidates only; no fixture-qualified pair | Blocked |
| Coordinates | Two independent city-capable families; coordinates copied from the winning city, never averaged | No fixture-qualified city pair | Blocked |
| ASN/prefix mapping | Current origin/prefix mapping with all MOAS origins preserved | Two ASN entries are rights-approved but fixture-missing | Blocked |
| Usage | Current direct classification evidence with conflict handling | Candidates only | Blocked |
| Proxy/risk reasons | Current approved evidence for each published reason | 21 subscription aggregators are one family and none is fixture-qualified | Blocked |
| Numeric quality | Two independent current complete-coverage risk families; all contributing layers assessed | No source declares complete coverage | Blocked |
| `/24` context | Current exact-address observations; no prefix imputation | No active exact-observation family | Blocked |
| RPKI | Current VRP data | Candidate only | Blocked |
| BGP origins/paths | Approved current MRT snapshots from at least two independent path families | MRT disabled; candidate sources only | Blocked |
| Relationships | Current directed relationship snapshot | Candidate only | Blocked |
| Tier-1 | Current relationships plus at least two independent current path observations | No qualified inputs | Blocked |
| Pages release | Complete manifest, hosted gates and exact-hash approval | No approved release | Blocked |

Synthetic data may satisfy test-fixture rows only. It never satisfies a capability row.

## P0 contract closure

P0 is the first implementation work package: it may add contract schemas, validators, fixtures and the hosted test harness. Application/compiler feature work in P1-P7 depends on its exit gate. This document review implements none of those changes and promotes no sources.

The following register records concrete gaps found in the current files. Each row needs an owning-contract amendment, an observable acceptance artifact and a focused regression where executable. An unresolved row blocks the P0 exit gate.

| ID | Contract gap and required decision | Owning files and acceptance evidence |
|---|---|---|
| C01 | VIA3 lacks section record layouts, section IDs/flags, dictionary references, address encoding, router entries, inherited overlays, presence/reason bit numbers, quantization and overflow rules. Define required/optional sections and deterministic IDs without serializing Go structs. | `docs/binary-format-via3.md`, `docs/data-model.md`: byte tables for every shard kind, IPv4/IPv6 and corruption vectors, schema migration behavior. |
| C02 | Strict schemas do not exist. Scope spellings include `exact`, `exact-ip`, `exact_ip` and `asn-edge`; BGP config uses `provider_transit` while public contracts use `transit_upstream`; assignment field aliases also differ. Separate source-schema fields from the public allowlist and define explicit normalization. | All five configs, `docs/source-policy.md`, validator: reject unknown/duplicate keys, invalid unions, duplicate IDs, bad hashes, invalid state combinations and unresolved aliases. No guessed parser or `unknown` format may become active. |
| C03 | Scoring YAML uses undefined `u_asn` and `C_asn_diversity`; `docs/scoring.md` substitutes `C_asn` for the latter. Define the quantities, scope/family dedupe, MOAS combination, coverage counting and rounding without changing coefficients by implication. Freeze weighted geo-vote denominators, hierarchy, winning-city selection and coordinate precision too. | `configs/scoring.yaml`, `docs/scoring.md`, `docs/data-model.md`: worked numeric vectors, order/idempotence/monotonicity cases and conflicting-country/city fixtures. Formula changes require an explicit versioned amendment. |
| C04 | Existing validation reads the obsolete `enabled` field and does not enforce admission, proof, rights or typed schemas. Rights-approved entries lack explicit no-attribution decisions. Freeze runtime failure classification, including future timestamps described as invalid in scoring docs and quarantined here. | `tools/validate_blueprint.py`, `configs/sources.yaml`, `docs/source-policy.md`: negative activation tests and a derived report with zero active sources. The old structural PASS is not this gate. |
| C05 | The executable CAIDA URL is dated; MRT is disabled, `max_mrt_sources_per_run` is 1, but path qualification requires two independent families. Two collectors from one family do not satisfy it. | `configs/sources.yaml`, `configs/tier1.yaml`: payload-bound discovery and a cold-build acquisition plan covering both families within existing budgets. Keep production MRT off while certifying its parser in isolation. |
| C06 | Header/decoded limits need strict boundary parity with Pages; native browser Zstandard support is assumed rather than demonstrated. | Binary/performance contracts and toolchain locks: reject assets at or above 24 MiB, prove bounded Zstandard decoding on the selected stable Chrome, and freeze browser worker/cache memory limits. No alternate codec or legacy fallback. |
| C07 | Session pinning and immutable caching do not define how an aging static release stops being current. Subscription expiry is shorter than 720 hours, and rollback can reintroduce withdrawn data. | Source/release/data contracts: aggregate release expiry, scheduling, client expiry checks, rollback eligibility and bounded private-cache/quarantine retention, with clock-advance fixtures. No source metadata is added publicly. |
| C08 | Release ID, manifest serialization and bundle digest inputs are not frozen. Approval points at `releases/current/manifest.json` instead of the release-ID path, and the source config's asset root differs from the object layout. | `docs/release.md`, `configs/release-approval.yaml`, `configs/sources.yaml`: canonical serialization, acyclic hash inputs, exact manifest-path resolution, inventory and approval tamper vectors. |
| C09 | Browser input cannot literally call Go `net/netip`; BGP-origin membership cannot be checked before loading the relevant prefix. Reserved ASN policy and duplicate/empty query parameters are unspecified. | `docs/data-model.md`, `configs/web.yaml`: Go/TypeScript canonicalization corpus, bounded input, route/query rules and distinct syntax versus membership-error tests. |
| C10 | Tier-1 core/cone/degree populations, near-complete-core algorithm, stability window and first-snapshot behavior are unspecified. Graph overflow can conflict with protected hops. | `configs/tier1.yaml`, data contract: deterministic derivation and graph-selection rules, missing-input/first-snapshot/overflow fixtures, with all existing thresholds preserved. |
| C11 | Performance gates lack sample protocols, byte accounting and a process-wide disk/memory envelope. Public scanning needs schema-aware rules so required OSM URLs and library syntax are not confused with leaked IP metadata. | `docs/performance.md`, release/web contracts: hosted measurement protocol, full inventory accounting, scanner positive/negative fixtures and generated-page CSP checks. |
| C12 | `SOURCES_AUDIT.md` says one subscription family per repository and calls starter records active; `VALIDATION_REPORT.md` still says starter-enabled. Neither overrides current admission. Historical sample results need their own evidence boundary. | `README.md`, `SOURCES_AUDIT.md`, `VALIDATION_REPORT.md`: one shared subscription family, accurate admission counts, dated evidence and explicit unrun gates. |

Pin the Go, Node/pnpm, Nuxt/UI, Motion, Leaflet and compression toolchains as P0 artifacts. Select a supported stable Go when implementation starts; a `go.mod` directive alone does not prove runner/toolchain support. Lock the compressor version and settings. Verify Chrome/codec behavior in hosted CI and record the actual browser build; do not infer it from the target label.

Create a minimal synthetic corpus for public records, all VIA3 sections, decoder syntax and URL semantics. Keep real source certification fixtures separate and build-private. Record the IPv4-only numeric-quality restriction, origin deep links, no-attribution proof and release-expiry semantics in their owning contracts before readers or UI depend on them.

Exit criterion: C01-C12 have resolved contracts and their required checks have run; unknown config fields fail; all public layouts are frozen; source states are unambiguous; the CAIDA/MRT contradictions are resolved; a derived capability report correctly reports every production row blocked on current data. Source qualification may continue later without blocking synthetic engineering work.

## Public data and VIA3

VIA3 is a versioned, little-endian, read-only, content-addressed container. The 64-byte header carries magic `VIA3`, format/schema versions, shard kind, flags, section-table offset, file and decoded lengths, and codec. Fixed 64-byte descriptors carry kind, codec, flags, offsets, lengths and SHA-256. Section descriptors are unique and sorted by kind. The release manifest separately carries the whole-file hash.

Readers must, in order:

1. Reject files shorter than the header or at or above the 24 MiB asset ceiling. C06 must reconcile the binary spec's currently inclusive wording with this strict deployment limit.
2. Validate magic, versions, header length, codec, reserved bytes and counts.
3. Validate table bounds and every descriptor with overflow-safe arithmetic before allocating decoded output. JavaScript must reject 64-bit lengths outside the supported bounded range before converting to `Number`.
4. Reject unknown required versions/kinds/codecs, duplicate or overlapping sections, truncation and out-of-bounds payloads.
5. Decompress with a hard output limit, then verify decoded length and SHA-256.
6. Reject trailing or unaccounted bytes.

Go and TypeScript readers consume the same golden corpus and must return byte-for-byte equivalent canonical answers and defined error classes. Bounds cover compressed input, decoder window, emitted output, record counts and dictionary references; advertised decoded length alone is not an allocation budget. Hash verification precedes exposure of a section. The browser verifies the manifest and each object hash before parsing and never falls back to another release or codec. Schema changes require a version bump, migration/rejection fixtures and matching reader updates; a manifest must never point an old reader at an incompatible schema.

Required shard families are router, geo, coordinates, network, usage, quality, IPv4 `/24`, ASN, RPKI, BGP origin, BGP path, BGP relationship, Tier-1 and dictionary. No source/provenance family exists. A compact router maps prefixes to content-addressed shards; planning repacks by bytes, not prefix count.

Freeze the lookup plan with C01: bounded-depth IPv4/IPv6 prefix routing, inherited ancestors at shard boundaries, exact-record precedence and an indexed ASN directory. A lookup must not scan all objects, prefix records or ASNs. The 256-cell view performs a bounded `/24` read; ASN prefix lists use an index and bounded paging. Dictionary/overlay references identify objects in the pinned manifest, and repacking cannot silently change their meaning. Test overlapping prefixes on both sides of a shard boundary, including an exact override and a withdrawn parent overlay.

Public records use integer references and presence masks. A zero value is valid only when its presence bit is set. Presence is independent for:

- coordinates, usage, assignment mode, anycast and IPv4 directed broadcast;
- quality and each of exact, explicit-prefix, ASN and neighbor risk layers;
- registration country and physical country;
- network identity, reason flags, RPKI and BGP facts.

Network identity stores a sorted multi-origin list, never a single arbitrary ASN. Quality stores `unrated` separately from score zero. Country registration and physical geolocation are separate facts. Organization/ISP labels are sanitized; URLs, domains, email addresses and credentials are removed, and an all-unsafe label becomes unknown.

Public records preserve unknown as unknown. No reader, UI component, aggregate or fallback may render a missing layer as safe, clean or zero.

## URL and query contract

Canonicalization happens locally before any query-specific database request. Loading the static application shell is independent of query validation:

- Go uses `net/netip`; the TypeScript browser parser must match its accepted address forms and canonical output using shared fixtures, without a runtime API. IPv4-mapped IPv6 is normalized to IPv4. Zone IDs, hostnames, URLs, CIDRs where an address is required, and malformed ASNs are rejected locally.
- An ASN accepts `AS<number>` or decimal digits, normalizes to `AS<number>` without leading zeroes, and rejects values outside the public ASN range.
- Invalid input remains on the current page with an inline error and performs no data request. It is not silently rewritten to an unrelated query.
- Missing `q` returns to `/ip`. Valid queries preserve `q` while navigating between subviews.
- C09 must define whitespace, case, empty/repeated `q` and `origin`, maximum input length, numeric overflow and the reserved/private ASN ranges. Malformed percent encoding and ambiguous repeated parameters fail locally; no decoder may interpret the same URL differently.

| Route | Behavior |
|---|---|
| `/` | HTTP 302 to `/ip`. |
| `/ip` | Exactly one IP/ASN input and no summary cards. IP submission goes to `/ip/overview?q=<canonical-IP>`; ASN submission goes to `/ip/asn?q=AS<number>`. |
| `/ip/overview` | IP only. Owns physical geography, map, ISP, usage, assignment and anycast. ASN query redirects to `/ip/asn`. |
| `/ip/quality` | IP only. Owns quality state, reason chips and layer contributions. ASN query redirects to `/ip/asn`. |
| `/ip/class-c` | IP only. IPv4 shows the owned 256-cell `/24` view; IPv6 shows an explicit not-applicable state. ASN query redirects to `/ip/asn`. |
| `/ip/bgp` | Accepts an IP or ASN. IP mode shows every origin and a deterministic origin selector; ASN mode shows that origin's observed paths and relationships. |
| `/ip/asn` | An IP query lists every origin for its prefix; an ASN query shows the ASN summary, risk, cone and prefixes. |

For `/ip/bgp?q=<IP>`, the default origin is the numerically lowest origin and the selected origin is represented as `origin=AS<number>`. Validate `origin` syntax before a query-specific request; validate membership after loading the verified prefix/origin record. An absent origin produces an inline error without requesting that unrelated ASN's paths or substituting an origin. A valid selected origin is preserved in its BGP deep link; `origin` is removed when `q` changes and is not carried as an active filter to other views. IP-in-ASN routes never choose an arbitrary primary ASN. Browser back/forward navigation restores the canonical query and selected path without leaking a prior query's result.

Reserved routes `/latency`, `/dns-leak`, `/webrtc`, `/cloudflare` and `/split` are not implemented. Direct visits must not imply that those tests exist.

Each fact has one display owner. `/ip/overview` owns physical geo/map/ISP/usage/assignment/anycast; `/ip/quality` owns quality and explanations; `/ip/class-c` owns the 256-cell grid; `/ip/asn` owns ASN risk and summaries; `/ip/bgp` owns paths, relationships, Tier-1 and per-origin RPKI. Other views link rather than repeat.

## Scoring, coverage and fusion

The equations, weights, half-lives and thresholds in `configs/scoring.yaml` are normative and remain provisional hypotheses, not calibrated probabilities.

For each signal and evidence family, take the maximum decayed contribution across observations. Reliability is `source_weight / 100`; specificity comes from the declared evidence scope; severity comes from the configured signal. Age uses item publication time when present, otherwise the verified source publication time. All terms are finite and clamped to their declared ranges.

Exact, explicit-prefix, ASN and `/24` are separate risk layers. Each layer has one status:

- `assessed`: current complete-coverage evidence supports both positive and negative observation across the layer's required scope.
- `positive_only`: positive observations may be shown, but absence is not an assessment.
- `unknown`: coverage is missing, stale, conflicting or otherwise ineligible.

A qualifying family must be current, fixture-tested, rights-approved without public attribution, complete for the relevant risk scope, and independent under `evidence_family`. Mapping sources and positive-only blocklists never qualify as complete risk coverage.

Numeric quality is emitted only when all four configured IPv4 layers are `assessed` and at least two independent current families qualify. Otherwise quality is `unrated`; confirmed reason flags and any observed layer contributions remain visible. Confidence is `low` for two qualifying families, `medium` for three, `high` for four or more, and `unrated` otherwise. Confidence describes coverage only.

Numeric quality v1 is IPv4-only because the configured neighbor layer is `/24`. IPv6 may show confirmed reasons and available layer facts but remains explicitly `unrated` until a separately specified IPv6 prefix-context model is approved; the system must not treat an absent IPv6 neighbor layer as zero risk by renormalization.

ASN risk is a capped contextual contribution, not inherited customer/provider guilt. For MOAS, compute context for every origin; if any origin required by the quality layer is unassessed, the ASN layer is `unknown` and numeric quality remains unrated. C03 must define how assessed per-origin values combine into the single IP-quality ASN contribution; selecting the first origin is not a rule. `/24` risk uses only exact-address observations, excludes the queried address, and counts each unique positive address and evidence family once. No unobserved host is imputed positive or clean.

The current equations are not yet executable contracts for every quantity: `u_asn`, `C_asn_diversity`, the disagreement with `docs/scoring.md`, and `/24` aggregate-quality semantics must be resolved in C03. Freeze family counting per assessed layer, signal aliases before dedupe, deterministic summation order, integer quantization and rounding. Keep unrounded internal contributions until the specified serialization step. Property tests compare like-for-like eligible coverage; a new positive observation must not make an eligible score better through a changed denominator or origin choice.

For geolocation:

- Each mapping family resolves its own longest-prefix match and contributes at most one vote per field; IPv4/IPv6 files from the same family never multiply support.
- Country uses source-weight-weighted plurality from current mapping families. An unresolved tie or unsupported conflict yields unknown.
- Region and city require two independent families and a winning margin of at least 0.15. Missing evidence from one family is not a vote for another.
- Coordinates and precision are copied from the winning city provider, never averaged or synthesized.
- Explicit anycast suppresses physical city, coordinates and map presentation. Any retained country/region is labelled by the fact actually supported; physical evidence must never be relabelled registration evidence to keep it visible.

Country, region and city must form a consistent hierarchy. Two participating families are not necessarily two agreeing families. C03 must define support for the winning place, the normalized winning margin and a deterministic winner among agreeing city families when their coordinates differ. Coordinates retain the winning provider's precision class; quantization must not create greater apparent precision. These rules require contract amendments rather than implementation defaults.

Usage requires direct classification; an unresolved conflict yields `unknown`. Proxy, VPN, Tor, datacenter, abuse, country or ASN facts never determine usage. Assignment mode and anycast remain unknown without explicit evidence. IPv4 directed broadcast is a separate technical flag.

Once quality is eligible, adding independent positive evidence cannot improve the score and duplicate family evidence is idempotent. The transition from `unrated` to a numeric score is tracked separately from the monotonicity requirement and must be covered by tests.

## BGP and Tier-1

Production MRT ingestion is disabled until all of the following exist: approved current MRT sources, payload-bound snapshot discovery, a tested bounded streaming parser, at least two independent current path families, and resource budgets that fit the standard runner. Build-private parser work uses bounded fixtures while the production flag remains off; it does not require first enabling an uncertified source. Until qualification, real-data BGP-dependent views fail closed with an unavailable state; synthetic engineering previews remain explicitly synthetic.

Reconcile the one-snapshot-per-run cap before activation. A cold build must acquire the required independent evidence, possibly through bounded acquisition stages, without depending on an undocumented previous cache. Reusing two current certified snapshots is allowed only when both are revalidated and their byte/proof identities are retained. Collector count and independent family count are separate quantities.

BGP origin and RPKI are prefix/ASN facts and are computed per origin. MOAS announcements preserve every origin. An AS_PATH observation is not a business relationship. Directed relationship data determines provider/transit, peer, customer or sibling; missing or conflicting relationship evidence yields `unknown`. `peer` is never a fallback.

AS paths are retained as observations with collector identity kept build-private. Canonical path encoding removes duplicate evidence without changing AS order. Preserve the uncollapsed observed ASN sequence; display-only prepend collapsing never changes source observations, visibility counts or hop meaning. A public sequence of ASN IDs is a BGP fact, not a raw publisher line or a provenance record. Paths containing AS sets or other non-linear constructs are retained as build facts where possible but excluded from a linear graph unless a deterministic representation preserves their real semantics.

P5 fixtures must cover collector-to-origin versus origin-outward orientation, prepends, loops, AS sets/confederations and four-octet ASN reconstruction. RPKI validation uses each actual announced prefix and origin against current VRPs, including maximum length and covering/multiple VRPs. Missing or invalid VRP input yields unavailable/unknown, never the `not_found` answer that requires a valid assessed VRP snapshot. Exact public enum values are frozen in C01.

Retain at most 12 unique paths per origin, ranked deterministically by relationship coverage descending, path length ascending, visibility descending, then canonical path bytes ascending. The graph projection then selects at most 24 nodes, two protected hops and three backbone exits per second-hop ASN. Freeze which paths are selected before protecting their first two hops; if the union exceeds the budget, deterministically select fewer complete path projections and disclose truncation. Never drop a protected hop to connect nonadjacent ASNs. Preserve observed-versus-inferred edges, relationship direction and Tier-1 trunk continuity. A collapsed display segment represents its real underlying sequence, not a new observed adjacency; unrelated gaps must not be merged. Route selection changes focus/visibility without reconstructing the graph layout.

Tier-1 is source-derived for each snapshot: provider-free relationship position, relationship-core/peer support, customer-cone/degree thresholds and independent path visibility. It requires current directed relationships and at least two independent current path observations. Missing or conflicting inputs produce `unknown`; zero observed upstreams alone is insufficient. C10 freezes the eligible ASN population, cone traversal/cycle rules, peer-core discovery, percentile ties and cross-snapshot stability/bootstrap behavior while preserving 0.80 core support and 0.98 cone/degree percentile thresholds. A fixed ASN list or repository description cannot fill the gap.

CAIDA snapshots must be discovered from the publication index and bound to a verified timestamp. A dated URL is not an executable default. The same rule applies to RouteViews and RIPE RIS snapshots.

## Frontend and privacy

The frontend is Nuxt 4 static generation with Nuxt UI first, shadcn-vue only for a genuinely missing primitive, one shared light/dark token system, Motion for interaction-driven transitions, and Leaflet lazy-loaded only on `/ip/overview`. TresJS is deferred beyond v1 to protect initial JS and accessibility budgets. No component may load remote data, source metadata or a runtime lookup API.

Design requirements:

- Minimal copy, generous whitespace, layered liquid-glass surfaces and thin masked edge lighting with accessible contrast.
- Light/dark parity for every state: loading, empty, unrated, stale/unavailable, error, partial and fully rated.
- Motion is purposeful and honors `prefers-reduced-motion`; no decorative infinite loop.
- The `/ip` hero has exactly one input and no summary cards.
- Dense graph labels do not use glass blur.
- The map shows OSM attribution, discloses approximate placement and never implies street-level precision.
- BGP uses native SVG with pan, pinch, wheel, fit, keyboard and path-focus controls. Exactly one graph is rendered.
- Responsive acceptance covers 320, 390, 1280 and 1440 pixel widths, with no horizontal overflow at 320.

Security and privacy:

- Requests are same-origin except `https://tile.openstreetmap.org` when a map is mounted.
- `Referrer-Policy: no-referrer` ensures `q` cannot reach OSM.
- CSP restricts script/style/data origins to same-origin and images to the necessary same-origin/data/OSM sources; generated inline script/style handling must be explicitly reviewed. Omit broad wildcards.
- `X-Content-Type-Options: nosniff` and a restrictive Permissions Policy are mandatory.
- No analytics, cookies, telemetry, remote fonts, remote icons or third-party embeds.
- Map and BGP chunks load only on their owning routes.
- A missing or corrupt release shows a fail-closed unavailable state with no stale render.

P1/P6 must define worker cancellation and query ownership: a late response for an earlier query cannot replace the current result. IndexedDB stores verified immutable objects under their hashes and schema/release identity, with bounded eviction; it is not an independent authority for freshness or current eligibility. Do not retain query history or secrets. Expired data is unavailable even when its checksum is valid.

Test the generated Nuxt output against the deployed CSP, including hydration, payload loading, workers, Leaflet styles and theme switching. Do not assume templates prove the generated site works. Any required inline script must have a reviewed static hash policy; do not relax `script-src` to unrestricted inline execution. The OSM attribution link and tile origin are permitted map requirements, not enrichment-source metadata.

## Build and data pipeline

The build is an explicit dependency graph:

1. Strictly validate configs, source admission, rights and dependencies before the production fetch set is selected. Candidate reconnaissance is a separate build-private operation.
2. Resolve deterministic source snapshots, enforce download bounds, and bind publication proof, coverage and observed schema to the exact payload.
3. Parse streaming input into typed normalized evidence; never retain post-parse `map[string]any`.
4. Deduplicate exact bytes, canonical records and evidence families without losing the private contributor index needed for retraction.
5. Partition and external-sort within declared RSS and scratch limits.
6. Recompute every partition invalidated by a source change, withdrawal, expiry, parser/schema/config change or mapping change.
7. Fuse geo, network, usage, quality, ASN, `/24`, RPKI, BGP and Tier-1 outputs deterministically and derive the capability report. An unmet production capability blocks promotion.
8. Encode content-addressed VIA3 objects, verify every object, compute conservative expiry and freeze the immutable manifest.
9. Generate Nuxt, copy the entire `_atlas` tree into `web/.output/public`, build the complete Pages inventory and scan public output.
10. Deploy that candidate to preview, run hosted gates and bind their results to its artifact digest.
11. Verify exact-hash approval and recheck expiry, rights/withdrawal state and all gates before promoting those same bytes. If revalidation changes the artifact, start a new preview/approval cycle.

Every fetch uses HTTPS, bounded redirects, private-network redirect rejection, per-host concurrency one, global worker caps, response-size limits and bounded retries. The build may resolve approved bulk-download origins; it must never resolve a host extracted from subscription content or user input. Validate initial destinations as well as every redirect, bind the connection to validated public addresses, and reject rebinding/private targets. Archive processing rejects traversal, links, duplicate/overlapping paths, excessive entries, invalid UTF-8 and decompression bombs. Writes are staged and atomic. Context cancellation stops all work and leaves no partial object eligible for release.

The source cache is an optimization only. A cold full rebuild must produce the same canonical public output as a warm incremental rebuild for the same inputs and evaluation clock. Freeze the evaluation clock for deterministic tests; item/source publication time still controls decay and expiry. Source changes invalidate dependent exact, prefix, ASN, `/24`, RPKI, path, relationship, Tier-1 and graph partitions. Recompute an affected partition from surviving evidence instead of subtracting rounded scores from the prior aggregate. Cache keys include normalized snapshot hashes, parser/schema versions and relevant policy/config hashes. Source-list deletion is a withdrawal, not a no-change build.

Use a clean, allowlisted publication tree. Repository files, source-sample manifests, audit reports, raw caches, quarantine, fixture payloads and private source configs must never be copied recursively into the public output. Freeze numeric retention and cleanup bounds in C07; raw subscription material stays in controlled build-local quarantine only and is removed after the bounded certification/build task.

## Delivery sequence and exit gates

No phase is complete until its exit gate has actually run in the repository. Static review or a written assertion is not execution evidence. The dependencies below schedule work; they do not waive `AGENTS.md` section 11. If a mandatory material-PR suite does not yet exist, record it as pending/blocking and use draft/integration checkpoints, never a skipped-pass claim.

| Phase | Depends on | Reviewable work product | Exit gate |
|---|---|---|---|
| P0 | Repository contracts | C01-C12 amendments, strict schemas/validator, synthetic corpus, toolchain locks, hosted harness and capability report | Register resolved; unknown fields and impossible states fail; zero active sources and every production capability blocked on the current catalog |
| P1 | P0 | Synthetic end-to-end release: typed records, writer, Go/TS readers, indexed router, worker, minimal static `/ip` and `/ip/overview`, manifest/inventory | Deterministic bytes and canonical answers; corruption/migration fixtures fail closed; hosted preview serves every synthetic object and is visibly synthetic |
| P2 | P0-P1 | Secure fetch, proof, archive handling, private lineage, source state machine, subscription decoders and source-certification reports | Initial/private redirect, size/bomb, cancellation, stale/304, withdrawal, decoder and family-dedupe regressions pass; candidate certification never enables publication implicitly |
| P3 | P1-P2 | Geo/network/usage fusion, inherited overlays, MOAS, coordinate ownership and sparse `/24` records | LPM/shard-boundary, conflict, presence, retraction and deterministic cold/warm resource checks pass |
| P4 | P2-P3 | Quality layers, unrated semantics, reasons, ASN and leave-one-out `/24` context, confidence/bias reports | Formula vectors, bounds, no-clean-from-absence, family idempotence, monotonicity, ASN cap, self-exclusion and bias sentinels pass |
| P5 | P2-P3 and C05/C10 | MRT/VRP/relationships, derived Tier-1, retained paths and bounded graph projection; production MRT activation remains a separate source gate | MOAS, origin-specific RPKI, reversed polarity, unknown versus peer, missing/stale inputs, first-snapshot behavior, route continuity and graph overflow tests pass |
| P6 | P1 shell, then P3-P5 | All canonical routes/deep links, lazy map/SVG graph, themes, accessibility, CSP/privacy and cache/error states | Hosted stable-Chrome route/network/responsive/keyboard/reduced-motion tests pass; no duplicate owner facts; obsolete query work cannot render |
| P7 | P0-P6 and qualified real sources | Immutable full candidate, fresh capability report, complete Pages preview, hosted quality/performance reports and exact-hash approval | Every mandatory gate and full inventory passes; approval/artifact/manifest hashes match; candidate remains eligible at promotion; rollback is still eligible |

The synthetic vertical slice may be demonstrated before real-source qualification. It is clearly labelled synthetic and cannot be used for production approval.

Source rights, exact-asset discovery and coverage certification form a continuing workstream from P0/P2 through P7. They need not block synthetic parser/UI development, but no phase test may relabel a synthetic capability as approved real-source coverage. In particular, finding a valid complete-coverage pair is a product dependency that code cannot supply.

Each implementation change records affected source schemas, VIA3 kinds/public fields, routes, resource budgets and regression fixtures before editing. Its evidence packet includes revision/config hashes, modified paths, hosted run and preview URLs, actual commands and outcomes, benchmark inputs/results, pending gates and assumptions. Publish only source-free public test reports; provenance-rich evidence remains build-private. A green subjob is not a completed phase or production approval.

## Required tests and acceptance evidence

### Configuration and source policy

- Strict schemas reject unknown YAML fields, duplicate IDs, invalid enum values and malformed hashes.
- Duplicate YAML keys, unresolved parser/scope aliases, cross-config enum conflicts and the obsolete `enabled` activation path are rejected.
- State tests prove no entry can become `active` with a missing/failed fixture, unavailable proof, unresolved rights, attribution requirement, invalid coverage or missing family.
- Tests prove all 21 subscription repositories share one family and mirrors/partitions do not create votes.
- Tests prove `304`, local mtime, fetch time, cache time and mutable GitHub branch commits cannot refresh age.
- Tests prove withdrawal removes prior contributions and triggers all dependent rebuilds.
- Clock-advance tests expire unchanged snapshots/items, honor the stricter subscription lifetime, retract source-list deletions and invalidate warm builds on policy/schema/config changes.
- Capability reports identify why each required capability is blocked without treating sanitized reconnaissance as a tested schema or complete coverage.

### Fetch and parser security

- Redirects to loopback, link-local, private, multicast, reserved and rebinding targets are rejected.
- Oversized bodies, slow bodies, excessive redirects, retries, cancellation, malformed archives, traversal paths, duplicate archive entries and decompression bombs fail closed.
- Subscription fixtures cover plaintext URI lines, Base64 wrappers, VMess JSON/Base64, VLESS/VMess/Trojan/SS/SSR/HY/HY2/TUIC/AnyTLS syntax, Mihomo YAML and sing-box JSON.
- Fixture assertions prove only literal public IPs survive; credentials, ports, protocols, SNI, hostnames, domains, URIs, labels and comments do not appear in bytes, logs, fixtures or caches outside controlled build-local quarantine.
- Bracketed IPv6, malformed ports, non-IP hosts, private/special IPs, malformed YAML/JSON, excessive line lengths, nested Base64 and repeated duplicates are covered.

### VIA3 and lookup

- Unknown versions, unknown shard/section kinds, unknown codecs, truncation, arithmetic overflow, bad offsets, overlapping sections, duplicate kinds, hash mismatch and decompression limits are rejected before unsafe allocation.
- Tests cover IPv4, IPv6, exact records, inherited prefix overlays, exact overrides, empty facts and multi-origin records.
- Go and TypeScript tests consume one golden corpus and compare canonical answers and failure classes.
- The browser verifies object hashes and fails closed without mixing releases.
- Length-boundary fixtures include exactly 24 MiB, overflowing 64-bit values, oversized decoder windows, invalid dictionary IDs and corrupt inherited overlays. Lookup tests assert bounded shard reads rather than scanning all shards.
- Latest-stable Chrome runs the actual Zstandard golden corpus, migration/rejection vectors and worker cancellation; support is measured rather than assumed.

### Scoring and fusion

- Positive-only absence produces `unrated`, not score 100.
- Duplicate families are idempotent; source order does not affect bytes or scores; added independent evidence does not improve an eligible quality score.
- ASN context is capped and never propagates one host's malice to every customer; `/24` self-exclusion and no-host-imputation hold.
- MOAS ASN context is origin-specific. Region/city require two families and the configured margin. Coordinates are never averaged.
- Residential/mobile bias sentinels and policy-driven conflict fixtures run before any production approval.
- Numeric vectors resolve every ASN symbol, MOAS aggregation and rounding boundary; geo fixtures test winner support, hierarchy, margin ties and coordinate ownership. Positive-only reason flags survive an unrated score.

### BGP and Tier-1

- Multi-origin announcements, per-origin RPKI, reversed provider/customer fixtures, peer/unknown distinction and missing relationships are covered.
- Tier-1 derivation fails to `unknown` when either path or relationship inputs are missing, stale or conflicting.
- Path selection is deterministic; graph projection stays within 24 nodes, two protected hops and three exits; observed and inferred edges remain distinct.
- AS-set/non-linear path fixtures prove the graph does not invent ordering.
- Graph overflow preserves protected hops of selected routes; prepends/reverse orientation/four-octet ASNs, RPKI maximum length and valid-snapshot `not_found` versus unavailable data are covered.

### Hosted browser, privacy and output scanning

- Playwright on a Pages preview uses current-stable Chrome and covers root redirect, all `/ip/*` routes, IP/ASN canonicalization, MOAS origin selection, IPv6 Class C state, invalid queries, themes, reduced motion and 320/390/1280/1440 widths.
- Network interception proves no external request except OSM tiles and no query reaches OSM through a referrer.
- Missing/corrupt shards show a fail-closed state; redirects and cache headers match the contract.
- Warm IndexedDB caches and long-open tabs refuse an expired release; no-change builds retract expired data. A late response cannot render a prior query. Back/forward and origin-membership errors preserve the intended route state.
- Public-output scans inspect HTML, JS, CSS, manifests and decompressed VIA3 string tables for source names/IDs/URLs, credentials, domains, protocol/port, collector, latency, timezone, postal and continent data.
- Scanner fixtures distinguish forbidden public metadata keys and known private values from library implementation tokens and the required OSM map origin/attribution. This is not a general permission for domains or source strings in IP records. Scan encoded strings and generated source maps as applicable; prevent private artifacts from entering the tree in the first place.
- The complete manifest inventory matches deployed assets; no 404, stale object or mixed release is allowed.
- Approval mismatch, post-preview byte mutation, an expired candidate, an ineligible rollback and orphaned/extra public objects block promotion. Verify the deployed root's actual 302 response, not only a Nuxt client redirect.

## Performance and resource gates

Measurements must come from the standard hosted runner and a hosted browser preview.

| Gate | Target |
|---|---|
| Cold full build | Under the catalog's 35-minute soft deadline; hard abort before RSS/scratch limits |
| Small-source incremental build | Under 8 minutes |
| No-change incremental build | Under 3 minutes |
| Peak build RSS | Below 6.5 GiB |
| Peak scratch | Below 10 GiB |
| Generated static tree | At most 3,072 MiB, within the complete 14 GiB runner disk envelope |
| Indexed Go lookup p95 | Under 2 microseconds |
| Cached browser lookup p95 | Under 15 milliseconds |
| Typical initial IP payload | Under 400 KiB compressed |
| Initial JS | Under 200 KiB gzip |
| Mobile LCP | Under 2.5 seconds |
| INP | Under 200 milliseconds |
| CLS | Under 0.1 |
| BGP interaction | 50+ FPS target at 24 nodes |
| Pages bundle | Under 18,500 files and under 24 MiB per asset |

Record p50/p95/p99, RSS, scratch, allocation count, input size and cold/warm behavior. Absolute thresholds gate the first release baseline; relative thresholds are added only after enough hosted samples. A failed threshold is fixed or explicitly reviewed as a regression; it is not silently replaced by a looser number.

C11 freezes the measurement protocol before collecting the baseline:

- Identify runner/browser versions, revision, config/input hashes, source-family counts, record/path counts and fixture versus real dataset. Use repeated samples and report their count and distribution; a synthetic throughput result does not establish full-dataset capacity.
- Measure the entire process group and physical disk high-water mark, including Go, Node, decoders, downloads, expanded input, external-sort runs, caches, current/previous objects and upload staging. `GOMEMLIMIT` is not an RSS bound. The 10 GiB scratch and 3 GiB tree ceilings are not independent disk reservations; leave room for the checkout and toolchains within 14 GiB. Stream expanded input, cap concurrent decoders and reclaim scratch before packaging.
- Define cold full, warm changed, warm no-change and expiry/withdrawal rebuild scenarios with identical input/evaluation clocks where comparison requires it. Measure end-to-end stages as well as hot/cold lookup latency; an incremental result must include required freshness revalidation.
- Fix the benchmark query corpus across IPv4/IPv6, exact/LPM/MOAS, sparse/large ASN and worst-case overlays. For the typical-IP payload gate, account for pointer, manifest, router, dictionaries and every initially needed object; report worst-case payload separately. Initial JS includes executed entry/worker dependencies, with lazy map/BGP costs reported separately.
- Specify hosted mobile emulation, network/CPU conditions and scripted search, map, Class C and graph interactions. Report observed LCP/CLS and interaction timings with their sample method; distinguish lab INP estimates from field evidence. An idle page or an absent metric is not a pass. Measure graph responsiveness during pan/zoom/path selection at the 24-node limit.

No budget is raised by this review. Browser decoded-memory/cache caps and sample counts still need to be frozen in P0; they must not be selected after observing a failing run.

## Release contract and approval binding

The static release layout is:

- `/_atlas/current.json`: revalidated pointer with `format_version`, `release_id`, `manifest_path` and `manifest_sha256`.
- `/_atlas/releases/<release_id>/manifest.json`: immutable release manifest identifying every object, byte size, SHA-256, shard kind and partition coverage.
- `/_atlas/objects/<sha256>.via3`: immutable content-addressed objects.

The client pins one release for the session, validates pointer structure, verifies the manifest against the pointer and objects against the manifest, and fails closed if anything is missing or corrupt. Hashes establish byte integrity against the pinned same-origin metadata; they are not upstream freshness proof. The client never falls back to another release or mixes objects from two releases.

C08 must freeze an acyclic identity chain: derive the release ID from a canonical source-free content descriptor, then serialize the final manifest, hash it, and write the pointer. The release ID must not require hashing a manifest that already embeds that same hash as its ID. Freeze JSON byte canonicalization, path validation, unique manifest entries, object ordering, schema/codec compatibility and bundle-digest inputs. Resolve approval's manifest path through the actual release ID; `releases/current/manifest.json` is not the proposed layout. Approval and provenance-rich reports remain outside the public bundle and cannot create a self-referential artifact digest.

### Static freshness and withdrawal

C07 must add a source-free aggregate validity bound to the release contract before implementation. It is no later than the earliest applicable expiry among contributing snapshots/items, including the stricter subscription lifetime, and is not `built_at + 720h`. Exact field names/encoding require a reviewed schema amendment. No per-source timestamp, family or expiry list is public.

Schedule refresh and certification early enough to replace the release before this bound. Reevaluate unchanged inputs and known withdrawals; a failed gate must not renew an old release's validity. The browser checks expiry before exposing cached results and after a suspended tab resumes, and clears rendered data when eligibility is lost. Freeze bounded same-origin pointer revalidation in C07 so known withdrawals can invalidate a pinned session; a replacement starts a new fully verified release-pinned session, never an object-by-object fallback. If a replacement cannot qualify, lookups remain unavailable. Static immutable bytes do not remain eligible merely because they are cached.

Publication eligibility is rechecked after preview/approval delays and immediately before promotion. If the candidate has expired, or any contributing source has been withdrawn under current policy, rebuild/repreview/reapprove rather than altering the signed-off manifest or extending its clock.

The normal deployment bundle contains the current and immediate previous eligible releases, sharing identical content-addressed objects. A previous generation that is expired or contains withdrawn/disallowed contributions is not a safe rollback and must not be kept as eligible data merely to reach a generation count. C07 must reconcile that exception with the current two-generation config before implementation; if no safe rollback remains, report that blocker explicitly.

The Pages planner verifies the entire asset inventory, rejects 18,500 or more files or any asset of 24 MiB or more, and checks every manifest entry against the deployed bytes. Count frontend files, control files and both retained generations; reject unreferenced database objects and private extras. Hashed assets and `/_atlas/objects` receive immutable caching; HTML and `current.json` receive revalidation. `/ /ip 302` remains in `_redirects`. A failed bundle or gate leaves the previous successful deployment intact, but cannot extend its data's eligibility beyond expiry or withdrawal.

Production approval is bound to the exact SHA-256 of:

1. `configs/sources.yaml` as reviewed;
2. `SOURCES_AUDIT.md` as reviewed;
3. the release manifest as built.

`configs/release-approval.yaml` must be default-deny, record the approver/time, use those exact hashes, and include the derived release ID. The booleans under `requirements` describe required checks; they are not test results. CI must independently verify bound evidence, not trust checked-in `true` values. No workflow may flip approval, alter hashes, or deploy when any required capability, hosted gate, output scan or inventory check fails. A preview and production deployment must use the same candidate artifact digest; rebuilding between approval and production invalidates approval.

Freeze the candidate tree before preview upload. Hosted reports identify its digest and preview deployment ID. After approval, promote the same artifact through an explicit protected production action; branch names or a successful sample-tool workflow are not authorization. Post-deploy read-only checks verify the production pointer/manifest hashes, actual root 302, cache/CSP headers and full object availability. A byte mismatch or missing asset is a failed deployment, even if upload succeeded.

Rollback selects a previously verified immutable artifact only after current freshness, rights, withdrawal and schema checks establish it is still eligible; a historical green run alone is insufficient. Keep that safe artifact until the replacement is verified. Freeze the numeric rollback/private retention windows in C07. Prune objects after retention when no eligible retained release references them, and remove disallowed generations from subsequent deploy trees. If no prior artifact is eligible, fail closed rather than restoring stale data.

## Execution blockers and review disposition

These are execution blockers, not optional backlog items:

- No source is active, and all 91 fixtures are missing. Production cannot start.
- No source declares complete coverage and no current complete-coverage pair exists for numeric quality; this requires an approved source/coverage correction, not a code default.
- Region/city/coordinates, usage, abuse/risk, RPKI, MRT paths, directed relationships and Tier-1 lack qualified current coverage.
- All seven rights-approved entries still need payload fixtures, publication proof, explicit `attribution_required: false` and final rights revalidation.
- MRT remains disabled until an approved source and parser pass the P5 entry criteria.
- The hardcoded dated CAIDA URL in the source catalog violates snapshot discovery and must be corrected during P0.
- VIA3's container framing is specified, but per-section record layouts must be frozen during P0 before implementation can claim parity.
- C01-C12 remain open until their owning contracts and acceptance evidence exist. This review documents their closure work; it does not assert that the accompanying configs, docs or validator have already been fixed.
- Browser Zstandard behavior, full-dataset runner capacity, static-release expiry, source-use permissions and a safe two-generation bundle remain unverified. Format samples and historical structural checks do not settle them.

The plan does not authorize a reduced production scope. If a capability cannot be sourced under the public-output and rights rules, the correct outcome is to keep production blocked or obtain an explicit product-scope decision; it is not to publish that capability as unknown, synthetic or inferred.

## Completion checklist

- [ ] P0 contracts frozen, strict configs validated, impossible states rejected and capability report generated.
- [ ] All public fields and VIA3 section layouts have deterministic byte-level definitions.
- [ ] C01-C12 are closed in their owning contracts, including ASN quantities, enum normalization, browser parsing and MRT cold-build independence.
- [ ] No source is active without a passing fixture, exact publication proof and redistribution rights.
- [ ] Source withdrawal and staleness remove all contributions and rebuild dependent partitions.
- [ ] No-change builds, client caches and suspended tabs enforce source/item/release expiry; rollback cannot restore withdrawn data.
- [ ] Subscription decoders retain only literal public IPs and one evidence family.
- [ ] Score, confidence, fusion, MOAS, ASN, `/24` and unrated invariants pass.
- [ ] BGP origins, RPKI, relationships, Tier-1 and graph projection preserve observed semantics.
- [ ] Go and TypeScript VIA3 readers pass the same golden and corruption corpus.
- [ ] Every `/ip/*` route, query edge case, theme, responsive width and fail-closed state passes hosted Chrome.
- [ ] Only same-origin assets and OSM tiles are requested; no query reaches OSM by referrer.
- [ ] Manifest, object hashes, Pages inventory, file/size limits and public-output scans pass.
- [ ] RSS, scratch, cold/warm build, lookup and browser performance measurements pass on hosted infrastructure.
- [ ] Hosted measurement protocols and sample counts are fixed; whole-process/whole-disk peaks and cold-query payload accounting are reported.
- [ ] Every capability matrix row is satisfied by approved current real-source coverage.
- [ ] Release approval binds the exact source catalog, rights audit and manifest hashes; deployment verifies the preview and production artifact digest matches.
- [ ] Rollback release remains available until the new release is verified.

The original refinement was a document review only. Its historical disposition did not claim implementation, activation, builds, tests or deployment. The 2026-11-08 implementation checkpoint and actual local evidence are now recorded in `docs/implementation-status.md` and `VALIDATION_REPORT.md`; hosted and production gates remain pending.
