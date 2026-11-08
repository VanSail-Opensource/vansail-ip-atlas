# Source Admission and Freshness Policy

## Static Admission States

- `candidate`: cataloged but not fixture-tested.
- `fixture_tested`: observed payload and parser fixture passed.
- `rights_approved`: a recorded redistribution decision permits the proposed derived product. This peer milestone alone does not establish explicit no-attribution permission or fixture certification.
- `active`: fixture-tested, rights-approved, and eligible for the current build.
- `retired`: withdrawn or legally excluded.

Runtime state is not stored in YAML. A source may be statically `active` but dynamically `stale`, `missing`, `invalid`, or `quarantined`.

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
- redistribution decision and rights evidence;
- dependency list.

Unknown fields are rejected. A source cannot be active without a validated fixture, current publication proof, and redistribution permission.

## Contract revision 1: executable admission

`schemas/*.schema.json` are reviewed, closed JSON Schema 2020-12 contracts. `tools/validate_blueprint.py` loads them without regenerating schemas from the submitted YAML. Duplicate keys, aliases, non-string keys, excessive nesting, nonfinite numbers and unknown properties fail. Policy values in all five configs are frozen by type and value; changing a coefficient, threshold, limit, route or policy requires a reviewed owning-contract/schema amendment. Source entries use reusable typed objects and tagged states; changing a candidate's URL does not rewrite its schema.

`parser: {id: null, schema: null, version: null}` is an explicit unresolved parser, not automatic format detection. No existing parser has been certified for production. A candidate may retain an `unknown` download format, but neither it nor a guessed parser can become active. Every source has separate raw `fields`, canonical `public_fields`, `signals` and `field_mappings`. The initial public lists/mappings are empty because reconnaissance did not certify field meaning. In particular, `country_code` does not automatically become a physical country and `organization_domain` never becomes a public label. IP/prefix selectors are parsed into typed record keys; they are not copied as arbitrary fact fields. Null mapping targets discard raw fields immediately. Every non-null target must be in both the source's public allowlist and the global public allowlist.

Source scopes are exactly `exact_ip`, `prefix`, `asn`, `asn_edge`, `path`. Historical `exact`, `exact-ip` and `asn-edge` spellings are rejected after this explicit catalog normalization. Public relationship classes are exactly `transit_upstream`, `peer`, `customer`, `sibling`, `unknown`; `provider_transit` is rejected. Internal `c2`, `scanner`, and `cloudflare_proxyip` signals map to `command_control`, `scanning`, and `proxy` reason bits, respectively. Assignment is `assignment_mode`; it is independent of anycast and `ipv4_directed_broadcast`.

An active source requires all of: nonempty parser ID/schema/version, an observed real fixture under `fixtures/source-certification/`, matching parser/schema and SHA-256, UTC test time, explicit field mappings, exact asset/discovery, explicit evidence family/coverage, and reviewed distribution permission with `attribution_required: false`. A `missing` fixture cannot carry a hash, observation claim or test date. Synthetic contract fixtures and `fixtures/source-samples/` never certify a source. `attribution_required: null` means unresolved; this revision sets no source to false and promotes no admission state. Rights/fixture milestones are peers and are independently checked on activation.

`fixtures/source-certification/adapter-certifications.json` is a reviewed build-private ledger, initially empty. A fixture milestone additionally matches its source ID, parser/schema/version, fixture hash/test time and current internal Go implementation hash in that ledger. Unknown parser strings and changed implementations cannot qualify by flipping YAML booleans. The ledger records independently reviewed parser-run evidence; the policy evaluator does not fabricate a parser run or discover licensing permission. Future source certification must execute the observed parser and review the corresponding evidence before adding an entry.

The P0 policy evaluator accepts trusted payload-verifier results only; it is not a network ingestor or proof verifier. P2 must construct these results from actual downloaded bytes, their schema validation, current policy, and asset-specific metadata. The CLI intentionally supplies no such results and consequently reports no current sources. A config label or checked-in report cannot produce a current payload. Build-private reports include config hashes, decisions and missing capabilities and must never enter `web/` or a deploy artifact.

The capability report counts distinct `evidence_family` values, explicit canonical fields and signal mappings. Numeric quality needs the same two complete families assessing all four layers. Usage cannot qualify from a provider name or a datacenter reason. The Pages row cannot qualify from config booleans; exact candidate evidence, preview and approval verification remain separate mandatory gates. Missing runtime evidence makes every data capability blocked even if a source is statically active.

## Event clocks, runtime failures and retraction

The publication clock must be tied to the exact payload hash. A GitHub commit qualifies only for a commit-pinned download or a verified blob belonging to that commit; a branch commit or release title is insufficient. No authoritative header origin is initially allowlisted. A timestamp more than 24 hours in the future is `quarantined`, not `invalid`; a smaller future skew has zero age and retains its original deadline. At `now >= published_at + 720h`, the snapshot is stale. Unknown/unbound proof is quarantined; corrupt/schema-invalid bytes are invalid; bounded acquisition exhaustion is missing.

Subscription evidence expires at the earliest of snapshot publication + 168h, verified upstream item publication + 168h, and the general 720h ceiling. An absent or unverified item publication timestamp quarantines the item; first local observation, fetch time and republishing a wrapper cannot establish item freshness. A newly wrapped old item never becomes new. All no-change builds must reevaluate these deadlines and current rights, policy, schema/config hashes, source-list deletions and retirement before any cache-hit return. HTTP 304 does not alter any deadline.

When eligibility is lost, the production pipeline must discard every previous contribution, mark the union of its exact/prefix/ASN/neighborhood/routing/graph dependent partitions dirty and recompile from surviving current snapshots. The P0 evaluator tests exclusion and time/withdrawal decisions; it does not claim that the P2 storage/rebuild pipeline exists. Private retention and current-output retraction are separate: bounded audit retention cannot keep any record eligible. Release-level expiry, client revalidation and rollback are defined in `docs/release.md`.

## Cold BGP acquisition

MRT remains disabled. A future cold build must acquire one selected RIPE RIS and one RouteViews snapshot sequentially, within the unchanged shared 1024 MiB compressed MRT budget and 2 vCPU/8 GiB/14 GiB envelope. Two collectors from the same family cannot qualify. `max_mrt_sources_per_run: 2` is a cold-build source allowance, not concurrent workers or a relaxed byte limit. If both snapshots cannot fit or freshness cannot be proved, block the release and report measured failure.

CAIDA serial-2 discovery chooses the newest matching `YYYYMMDD.as-rel2.txt.bz2` filename, with canonical URL bytes breaking equal-date ties, from its fixed directory. The filename/date and directory mtime select a candidate only; neither is a publication proof. The hardcoded dated download was removed without asserting that a fresh redistributable payload exists. See `docs/bgp-tier1.md` for independent path-family qualification and deterministic derivation.

## Evidence Independence

The 21 proxy-subscription repositories all use `evidence_family: public-subscription-aggregators`. Repetition across those repositories counts once. Protocol partitions and mirrors from one publisher also share a family. A new family requires documented original-source provenance.

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

Public hosting of a derived database can constitute redistribution. Sources requiring public attribution or prohibiting redistribution are excluded. OpenStreetMap tile attribution is a map-service requirement and is not database provenance.

## Production Capability Gate

Production is blocked unless approved current sources exist for every promised capability:

- at least one geolocation family for country;
- two independent families for region/city/coordinates;
- current ASN/prefix mapping and usage classification;
- proxy/risk reasons and exact `/24` observations;
- two independent complete-coverage risk families for numeric quality;
- current MRT paths, directed relationships, origin data, and RPKI for BGP/Tier-1.

No allowlist, placeholder source, or synthetic record satisfies the gate.
