# Source Admission and Freshness Policy

## Current release scope `release-scope-v6` - 2026-11-15

The approved model is `via-observed-risk-v1`: positive-evidence observed risk
with explicit incomplete coverage. All categories and product views remain
supported. Production requires verified positive observations, not a feed for
every category; missing categories and unlisted addresses remain unknown.
Complete negative assessment is never inferred. Prior v2 optional numeric-quality
rules are superseded by this versioned model. Global credits remain required;
the educational source-use amendment below supersedes blanket compiled-data
license compatibility as an admission prerequisite.

Each dataset needs an explicit reviewed source-use decision, actual publication
proof and an observed parser fixture. The product license does not approve a
source or replace upstream terms. V5 additionally permits required
publisher logos in the single global credit display, with no per-IP attribution.
The source config is schema3/contract revision5, public VIA3 schema5, private
normalized records schema3. Credit documents use format2 and their index format1.
The private capability report remains schema3 with release-scope-v6.

## Static Admission States

- `candidate`: cataloged but not enabled for intake; an observed fixture may already be tested while exact-code certification or final integration remains pending.
- `fixture_tested`: observed payload and parser fixture passed.
- `rights_approved`: a recorded source-use decision permits project admission under this policy. This milestone does not assert a publisher grant, attribution compliance or fixture certification.
- `active`: fixture-tested and rights-approved, with controls permitting attempted intake; current build eligibility still requires actual runtime proof.
- `retired`: withdrawn or legally excluded.

Runtime state is not stored in YAML. A source may be statically `active` but dynamically `stale`, `missing`, `invalid`, or `quarantined`.

The November 15 v6 release catalog has fifteen reviewed sources enabled for attempted intake, including five replacements. The replacements are complete WIDE and RRC18 collector snapshots, CAIDA serial-2 relationships, complete RPKI publisher snapshots, and FFraud observations. Their exact observed fixtures and required global legal assets are present; implementation-bound certification is refreshed only after the integrated Go code is frozen and all fifteen observed fixtures rerun. Active status permits attempted acquisition; facts, coverage and credits require independent admission from complete current source bytes. Static status cannot establish current production coverage. See SOURCES_AUDIT.md.

## Required Source Fields

Every entry declares:

- `evidence_family`: the sole independence key for scoring.
- `source_group`: operational grouping for multi-file publishers.
- parser and expected schema;
- fixture status and SHA-256 when tested;
- download/discovery rule and resource limits;
- publication proof;
- coverage kind and evidence scope;
- canonical public fields;
- explicit distribution decision, reviewed terms evidence and review basis;
- dependency list.

Unknown fields are rejected. A source cannot be active without a validated fixture, current publication proof and a permitted reviewed source-use decision.

## Contract revision 1: executable admission

`schemas/*.schema.json` are reviewed, closed JSON Schema 2020-12 contracts. `tools/validate_blueprint.py` loads them without regenerating schemas from the submitted YAML. Duplicate keys, aliases, non-string keys, excessive nesting, nonfinite numbers and unknown properties fail. Policy values in all five configs are frozen by type and value; changing a coefficient, threshold, limit, route or policy requires a reviewed owning-contract/schema amendment. Source entries use reusable typed objects and tagged states; changing a candidate's URL does not rewrite its schema.

`parser: {id: null, schema: null, version: null}` is an explicit unresolved parser, not automatic format detection. A candidate may retain an `unknown` download format, but neither it nor a guessed parser can become active. Every source has separate raw `fields`, canonical `public_fields`, `signals` and `field_mappings`. Unreviewed public lists/mappings remain empty; admitted sources require observed field meaning and explicit mappings. In particular, `country_code` does not automatically become a physical country and `organization_domain` never becomes a public label. IP/prefix selectors are parsed into typed record keys; they are not copied as arbitrary fact fields. Null mapping targets discard raw fields immediately. Every non-null target must be in both the source's public allowlist and the global public allowlist.

Source scopes are exactly `exact_ip`, `prefix`, `asn`, `asn_edge`, `path`. Historical `exact`, `exact-ip` and `asn-edge` spellings are rejected after this explicit catalog normalization. Public relationship classes are exactly `transit_upstream`, `peer`, `customer`, `sibling`, `unknown`; `provider_transit` is rejected. Internal `c2`, `scanner`, and `cloudflare_proxyip` signals map to `command_control`, `scanning`, and `proxy` reason bits, respectively. Assignment is `assignment_mode`; it is independent of anycast and `ipv4_directed_broadcast`.

An active source requires all of: nonempty parser ID/schema/version, an observed real fixture under `fixtures/source-certification/`, matching parser/schema and SHA-256, UTC test time, explicit field mappings, exact asset/discovery, explicit evidence family/coverage, and a permitted reviewed source-use decision. Attribution must be explicitly resolved: `attribution_required: false` records that no public credit is required; `true` requires valid reviewed `license.attribution` metadata and a global display that satisfies its obligations; `null` remains unresolved and blocks admission. A `missing` fixture cannot carry a hash, observation claim or test date. Synthetic contract fixtures and `fixtures/source-samples/` never certify a source. This scope amendment promotes no admission state. Rights/fixture milestones are peers and are independently checked on activation.

Source contract revision 2 adds the closed `license.attribution` object with
required `name`, `text`, `url` and optional `license_url`. Name is 1–128 characters,
plain text is 1–2048 characters, and URLs are at most 2048 characters, public
HTTPS destinations without credentials/private addresses, queries, fragments,
backslashes or raw angle brackets/quotes. Name/text are trimmed NFC Unicode
without controls, formatting controls or invalid surrogates. Subscription URIs,
private-key headers and credential-token markers remain forbidden in all fields.
HTML-looking literal text is escaped for display and never interpreted as markup.
Metadata requires a
permitted reviewed distribution decision, terms evidence URL and recorded review basis. Terms
requiring more notice/link obligations than this display can satisfy remain
ineligible until a reviewed compatible representation exists. Exact credit bytes
participate in private policy/source fingerprints and candidate approval; a changed
or withdrawn obligation invalidates prior eligibility and rebuilds release credits.

The private report may bind eligible attribution metadata to `source_id` in
`dataset_attributions`. That internal binding is never copied to a public credit.
The packager selects only actual included real dataset contributions, strips IDs
and private lineage, deduplicates identical reviewed credit entries and emits the
dedicated global credit artifact. Merely cataloged, candidate, missing, stale,
withdrawn or synthetic datasets cannot acquire a displayed inclusion credit.

`fixtures/source-certification/adapter-certifications.json` is a reviewed build-private ledger, originally empty and now populated for the reviewed subset. A fixture milestone additionally matches its source ID, parser/schema/version, fixture hash/test time and current internal Go implementation hash in that ledger. Unknown parser strings and changed implementations cannot qualify by flipping YAML booleans. The ledger records independently reviewed parser-run evidence; the policy evaluator does not fabricate a parser run or discover licensing permission. Any new or renewed certification must execute the observed parser and review the corresponding evidence before adding an entry.

The P0 policy evaluator accepts trusted payload-verifier results only; it is not a network ingestor or proof verifier. Actual intake constructs receipts from complete downloaded bytes, schema validation, current policy and asset-specific metadata. `validate_blueprint.py` intentionally supplies no runtime snapshots and therefore reports no current sources; the authenticated production path independently reopens surviving normalized partitions. A config label or checked-in report cannot produce a current payload. Build-private reports include config hashes, decisions and missing capabilities and must never enter `web/` or a deploy artifact.

The report has twelve required rows: eleven source capabilities and Pages.
Verified positive observations qualify risk; absent reasons remain unknown and
are informational. There is no legacy optional numeric_quality row. Usage requires
typed direct evidence or the reviewed ASN-category join. Two independent path
families, directed relationships and complete current RPKI remain required.
Pages needs the exact candidate's hosted preview and promotion gates.

Source revision4 adds optional license.attribution.logo, exactly {path, sha256,
alt}. Its public path is /_atlas/legal/<sha256>.png; the reviewed input is
fixtures/source-certification/logos/<sha256>.png. Alt text obeys credit-name
restrictions. Each PNG is at most 256 KiB and 512 x 512 pixels, non-interlaced 8-bit
grayscale/RGB with optional alpha, with only IHDR/IDAT/IEND chunks. Embedded
metadata, SVG, animation and trailing bytes are rejected. A release permits at
most 32 distinct logos and 4 MiB of logo bytes. Rights digests include logo metadata;
packaging verifies actual bytes and the complete frozen inventory. Missing,
altered, orphaned and symlinked files fail. The browser verifies credit and logo
hashes before exposing production lookup/ClassC facts and renders those verified
bytes. Required links/logos stay visible when notices are collapsed.

## Event clocks, runtime failures and retraction

The publication clock must be tied to the exact payload hash. A GitHub commit qualifies only for a commit-pinned download or a verified blob belonging to that commit; a branch commit or release title is insufficient. No authoritative header origin is initially allowlisted. A timestamp more than 24 hours in the future is `quarantined`, not `invalid`; a smaller future skew has zero age and retains its original deadline. At `now >= published_at + 720h`, the snapshot is stale. Unknown/unbound proof is quarantined; corrupt/schema-invalid bytes are invalid; bounded acquisition exhaustion is missing.

Subscription evidence expires at the earliest of snapshot publication + 168h, verified upstream item publication + 168h, and the general 720h ceiling. An absent or unverified item publication timestamp quarantines the item; first local observation, fetch time and republishing a wrapper cannot establish item freshness. A newly wrapped old item never becomes new. All no-change builds must reevaluate these deadlines and current rights, policy, schema/config hashes, source-list deletions and retirement before any cache-hit return. HTTP 304 does not alter any deadline.

When eligibility is lost, the production pipeline must discard every previous contribution, mark the union of its exact/prefix/ASN/neighborhood/routing/graph dependent partitions dirty and recompile from surviving current snapshots. Bounded and partitioned reconciliation apply these decisions before materialization. Private retention and current-output retraction are separate: bounded audit retention cannot keep any record eligible. Release-level expiry, client revalidation and rollback are defined in `docs/release.md`.

## Cold BGP acquisition

The dedicated MRT coordinator enforces two reviewed independent families, sequential acquisition and the unchanged shared 1024 MiB compressed MRT budget within the 2 vCPU/8 GiB/14 GiB envelope. The current cold-build plan selects one RIPE RIS and one RouteViews snapshot; other explicitly reviewed authoritative MRT sources may use cold intake without acquiring the recognized providers' replay privileges. The source allowance is two logical sources, not concurrent workers or a relaxed byte limit. Failed body reads and oversize probes consume the same non-resettable byte ceiling. If both snapshots cannot fit or freshness cannot be proved, block the release and report measured failure. Implemented coordinator tests do not enable or certify catalog entries; actual rights, observed fixtures and full-payload gates remain mandatory.

For the explicit embedded proof field `mrt_frame_capture_timestamp`, every MRT common header must pass complete framing and the 720-hour age/future-clock checks before the earliest capture establishes publication. SHA-256 binds that clock to the exact bytes, and retained identical bytes keep the earliest verified clock. TABLE_DUMP_V2 entry originated time is retained privately and does not expire an otherwise fresh captured RIB merely because a route was first heard more than 720 hours ago.

The explicit optional `download.mrt_archive_policy: latest-complete-v1` permits rotation only for canonical RouteViews WIDE bzip2 RIBs and RIS RRC18 gzip RIBs. The configured dated URL and publication locator remain stable collector/codec anchors in the catalog hash. At intake, subtract a 30-minute publication allowance and select the newest scheduled two-hour WIDE or eight-hour RRC18 slot. Only a header-only HTTP 404 permits one attempt at the immediately preceding slot; transport, authentication, rate-limit, size, hash, parser or capture-clock failures cannot select an older archive. Successful downloads still require complete framing and EOF within every existing byte/record limit. All capture clocks must fall within the selected slot and no later than the original selection time. The private state seal binds the actual archive URL and selection time, payload hash and capture interval; receipt revalidation and UPDATE replay use that actual base while preserving its original publication deadline. An absent policy retains fixed-URL acquisition. The reviewed catalog amendment enables only WIDE and RRC18, with matching closed collector controls. This implementation alone cannot activate another source or refresh its observed-parser certificate.

Incremental replay additionally requires a separately reviewed, code-bound `mrt_updates_fixture` for the BGP4MP schema. Its optional presence never waives the primary RIB certificate or rights checks. A sealed RIB can advance only through complete contiguous same-collector archives and an unambiguous RIB peer-to-transport-session join. Replay is bounded to one million logical update events / 180 seconds across both families and a 128 MiB changed-route working estimate. Missing proofs, unsupported sessions, gaps or exhausted replay limits trigger cold acquisition using the remaining shared budget; they never manufacture current paths. A replayed snapshot keeps the base RIB's original publication deadline and records the actual contiguous logical capture-through clock privately.

CAIDA serial-2 discovery chooses the newest matching `YYYYMMDD.as-rel2.txt.bz2` filename, with canonical URL bytes breaking equal-date ties, from its fixed directory. The filename/date and directory mtime select a candidate only; neither is a publication proof. The hardcoded dated download was removed without asserting that a fresh redistributable payload exists. See `docs/bgp-tier1.md` for independent path-family qualification and deterministic derivation.

## Evidence Independence

The 21 unqualified subscription entries were removed from the production catalog. Their independent security fixtures remain. Future reviewed derivative subscription lists must share `evidence_family: public-subscription-aggregators`; repetition counts once. Protocol partitions and mirrors from one publisher also share a family. A new family requires documented original-source provenance.

Reconciliation also correlates byte-identical current payloads before binding
any normalized record to a family. Configured families connected by identical
payload hashes form one private evidence group, including transitive bridges.
The lexicographically smallest configured family is its deterministic private
key. Ineligible snapshots cannot change this grouping; withdrawal recomputes it
from surviving sources. This prevents copied snapshots from manufacturing
independent risk, geolocation or path-visibility votes. It changes no coefficient
and emits no family key in public data.

## Publication Freshness

The only accepted clocks are:

- an embedded publisher timestamp;
- publisher release metadata explicitly describing the payload;
- an allowlisted authoritative publication header.

Fetch time, cache time, `Last-Modified` from an untrusted mirror, file-system time, and HTTP `304` do not establish freshness. Missing proof quarantines the source and removes all derived records.

Maximum age is 720 hours. Stale observations are deleted, never hidden behind a previous cache or manifest. Any changed or withdrawn source causes its dependent exact, prefix, ASN, `/24`, Tier-1, and graph partitions to be rebuilt.

## Download Security

- HTTPS only, with bounded redirects and private-network redirect rejection.
- Per-host concurrency of one and a global worker cap.
- Hard limits for compressed bytes, decoded bytes, lines, archive entries, parser depth, JSON/YAML size, and extracted IPs.
- Reject archive traversal, links, duplicate/overlapping output paths, malformed UTF-8, and decompression bombs.
- Never execute downloaded content, connect to a proxy, resolve a discovered domain, or recursively follow a subscription link.

## Subscription Decoder

Only literal public IPs are accepted. Credentials, ports, protocols, transports, URIs, labels, SNI, hostnames, and comments are stripped immediately. Each repository, even if it publishes several protocol files, contributes to the shared evidence family.

## Rights

### User-approved educational source-use amendment — 2026-11-15

The user explicitly authorized educational project use without requiring compatible
publisher redistribution permission. `license.distribution` records the exact
decision: `allow` preserves the existing reviewed permission path;
`user_authorized_educational_use` is a distinct user-authorized project decision.
It does not assert that educational purpose grants legal permission, that the
publisher agreed, or that upstream material can be relicensed under CC BY-SA.
`deny`, pending `review`, `unknown` and every unrecognized value still block admission. No global
boolean enables sources, and this amendment activates no catalog entry.

Both permitted decisions require `status: reviewed`, a public HTTPS `evidence_url`
for the reviewed terms, a nonblank `review_basis`, an explicit boolean
`attribution_required`, and valid exact notices whenever required. Retain the
publisher's identifier, terms and obligations as evidence; never replace them
with a fabricated permission or mark unresolved attribution as unnecessary.
For an educational decision, the review basis records the user's project-use
authorization separately from what the publisher terms establish.

The global contracts name the policy accurately:
`publish_only_reviewed_distribution_decisions`,
`active_requires_reviewed_distribution_decision`, and
`requires_reviewed_distribution_decision` remain true. The public source-rights
policy is `reviewed-distribution-decision-with-required-global-dataset-credits`.
Source schema3 and `release-scope-v6` remain unchanged because no normalized or
public record shape changes. Config/catalog/policy hashes bind the new decisions;
rights digests independently include distribution, terms evidence, review basis
and exact credit bytes. A changed decision or notice invalidates prior
qualification. Withdrawal, expiry or missing required credits retracts data.

Public hosting can constitute redistribution. This amendment changes the
project's admission decision, not upstream obligations. Original compilation
contributions retain their stated license; upstream material retains its own
terms. The frozen data-terms notice and reviewed global credits preserve that
distinction. Attribution does not waive redistribution, share-alike or other
applicable terms. Freshness, certification, parser safety, source independence,
performance and exact-candidate publishing gates remain unchanged.
The renderer escapes plain text and renders only reviewed safe links; it executes
no downloaded HTML or script. Credits make no per-IP provenance assertion and
cause no automatic request to a publisher. OpenStreetMap tile attribution remains
a separate map-service condition; software distribution notices are also separate.

## Production Capability Gate

Production is blocked unless approved current sources exist for every required capability:

- at least one geolocation family for country;
- two independent families for region/city/coordinates;
- current usage classification;
- proxy/risk reasons and exact `/24` observations;

Routing capabilities (ASN/prefix mapping, paths, relationships, RPKI and Tier-1)
are optional under the explicitly approved v6 scope. Their actual availability is
still derived and bound into the private receipt; missing data stays unknown.
Every included record and source must independently pass rights, publication,
parser and expiry checks. At least one authenticated source must be included.

Observed risk requires positive evidence from a qualified family and follows
configs/scoring.yaml exactly. Unlisted addresses and absent categories stay
unknown. Mapping records, mirror counts and synthetic fixtures do not establish
assessment coverage or source qualification.

No allowlist, placeholder source, or synthetic record satisfies the gate.

## Direct ASN identity CSV adapter

The engineering adapter `asn-identity-csv`, schema
`asn-handle-description-country-csv-v1`, accepts exactly
`asn,handle,description,country-code`. Its explicit public targets are `asn`,
`as_name`, `organization`, `asn_country`; it cannot map ASN country to IP geography.
It streams bounded logical CSV records, including quoted commas/newlines, and
returns private read/accepted/reserved-skip/sanitized-field counters. Decimal ASN
syntax is required. Reserved ASNs abstain through the shared public-ASN predicate
instead of invalidating an otherwise valid publisher file.

Implementing this parser is not source certification. The observed publisher
CSV has 125,830 rows and is supported by version-2 partitioned intake. The
100,000-record and 64-MiB decoded limits apply to each partition, not the complete
source; whole-store and runner budgets remain unchanged. Exact publication proof,
reviewed rights and current real-fixture certification remain mandatory on every
intake, independently of the reviewed source's static active label.

## Tor and contextual ASN usage

Tor intake validates complete TorDNSEL descriptors, strips relay metadata and
retains literal public exit addresses with original ExitAddress clocks. The
newest accepted observation conservatively dates the body; each older item clock
clamps expiry. Unlisted addresses are never declared non-Tor.

Ipverse JSON keeps metadata.lastModified for unambiguous hosting/business/
education/government categories. ISP/null does not imply residential/mobile.
ASN primary function is fallback context on current observed origin prefixes.
Direct IP/prefix usage wins; more-specific origin boundaries apply and mixed or
missing MOAS classification stays unknown. networkRole never establishes Tier-1.
File-specific commit proof downloads the complete immutable payload and matches
its SHA-256 and size; a fresh wrapper cannot renew an old category observation.

Source contract revision 5 records the educational-use decision and explicit
reviewed-distribution policy names. Normalized schema, VIA3 and public schema
versions are unchanged; exact configuration hashes invalidate older qualification.

## User-approved RPKI snapshot observations — 2026-11-15

RPKI results describe the complete exporter snapshot at its authenticated embedded
publisher build time. They do not assert the current global authorization state.
The user explicitly requested keeping expired results visible. Retain all VRPs,
including those whose authorizations expire between publisher build and intake;
require each original authorization deadline to follow the actual publisher build
time. Preserve AS0 and reserved/private authorization ASNs for correct observed
invalid/not-found classification. Never replace the clock with intake time or
remove still-valid short-lived rows to create a longer apparent lifetime.

The version-2 private proof binds the full original body, all five trust anchors,
exact original/retained row counts, observation time, intake evaluation time and
the earliest authorization expiry of the complete snapshot. The source content
expiry field remains zero for this explicit proof kind: snapshot eligibility is
still bounded by the original verified publication time plus its configured
maximum age, never more than 720 hours. Old version-1 proofs retain their original
strict expiry behavior and cannot establish a complete historical publisher epoch.

Observed valid results retain the latest deadline among matching authorizations;
observed invalid/not-found results carry the conservative complete-snapshot
coverage deadline. The public schema carries the real observation time and this
deadline alongside the observed result. Passing the deadline changes its visible
as-of/expired indication, not the historical result. No interface may present it
as current authorization. A single observed clock cannot describe a union of
different publisher epochs or unauthenticated partial rows; reject that cohort.
The rest of the website does not expire because one authorization did.

Expired authorizations remain eligible only as dated observations within a fresh,
rights-approved snapshot. Publication-age expiry or withdrawal still retracts
that source and its dependent output under the existing retention and garbage
collection rules. Retained generations and no-change cache hits preserve original
clocks, proofs and exact policy bindings; they never renew observation age. This
amendment is RPKI-specific and changes no subscription or other item expiry.
