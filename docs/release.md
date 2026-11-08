# Release and deployment contract v3.1 (P0 amendment)

This contract freezes C07/C08; its executable vectors are
`tools/release_contract/test_contracts.py`. Passing these vectors does not certify
a real dataset, a complete binary scanner, a hosted preview or a production release.

## Identity and canonical bytes

The identity chain is acyclic. Build a source-free content descriptor, hash its
canonical bytes to derive `release_id`, append `release_id` to form the manifest,
hash the final manifest, then write the pointer. Never derive the ID from a manifest
already containing that same ID. SHA-256 is lowercase 64-character hexadecimal.

Canonical JSON v1 has UTF-8 without BOM or trailing newline, NFC strings, ASCII
object keys sorted lexicographically, no insignificant whitespace and JSON escaping
equivalent to `json.dumps(ensure_ascii=False, sort_keys=True, separators=(',', ':'))`.
Numbers are integers in the JavaScript exact range `[-(2^53-1),2^53-1]`; no floating
point, exponent, NaN or infinity is permitted. Duplicate keys, invalid UTF-8 and
noncanonical encodings fail. Arrays retain their specified semantic order.

The descriptor has exactly these keys:

| Key | Encoding |
|---|---|
| `format_version`, `schema_version` | Integer `3` |
| `codec` | `zstd-1` |
| `mode` | `synthetic` or `production`; synthetic cannot be approved |
| `valid_from` | Nonnegative UTC Unix seconds; evaluation clock, not an upstream clock |
| `valid_until` | UTC Unix seconds, strictly greater than `valid_from` |
| `objects` | Nonempty array, sorted by unique ascending whole-file hash |

Each object has exactly `sha256`, `bytes`, `kind`, `partition`. `bytes` is the
whole compressed VIA3 file length, `64 <= bytes < 24*1024*1024`; `kind` is a VIA3
shard ID `1..14`. `partition` is `all`, an address partition
`4:<32-lowercase-network-hex>/bits` or `6:<32-lowercase-network-hex>/bits`, or the
inclusive ASN range `asn:<first>:<last>`. Address bytes and prefix masks follow the
binary address contract, and ASN ranges are ordered, public, disjoint within each
kind. An object hash belongs to one shard kind and partition. Router and overlay
references resolve only to this descriptor's object inventory. P1 must add the
cross-object coverage checks alongside the indexed router.

The manifest is exactly the descriptor's fields plus `release_id`. The pointer is
exactly `format_version`, `release_id`, `manifest_path`, `manifest_sha256`. Paths:

- `/_atlas/current.json`: revalidated pointer.
- `/_atlas/releases/<release_id>/manifest.json`: immutable manifest.
- `/_atlas/objects/<sha256>.via3`: immutable complete objects.

The pointer path must equal the path constructed from its verified ID. Reject
`current` aliases, traversal, queries, fragments, escaped separators, backslashes,
external origins and incompatible versions. Read pointer, verify manifest hash,
verify descriptor-derived ID, verify expiry, then verify each complete object hash
before interpreting bytes. No partial publication or mixed-release fallback exists.

## Expiry, withdrawal and suspended sessions

`valid_until` is the minimum applicable contributing observation expiry, never
`built_at + 720h`. A normal snapshot expires at its verified publication clock plus
720 hours. A subscription snapshot and each retained subscription item expire after
168 hours from their own verified clocks: use the earliest of snapshot and item
expiry. Missing verified upstream item publication time quarantines that item;
first observation, fetch time and snapshot republication cannot invent its clock.
The payload itself still requires exact upstream publication proof. A stricter reviewed source limit wins. Public
metadata exposes only aggregate `valid_until`, no source-specific expiry list.

Eligibility is `valid_from <= now < valid_until`; equality at expiry is ineligible.
The evaluation clock and all upstream clocks are UTC. Future publication tolerance
and quarantine follow the source policy. No-change builds reevaluate every expiry,
catalog deletion, rights withdrawal, policy/schema/config hash and prior source
state before accepting any cache hit. Retraction rebuilds every dependent block;
the new aggregate bound cannot extend an expired observation.

A client checks expiry before every cached result, query and render, on visibility
resume, and at an expiry timer. It clears rendered data when the bound is reached.
It revalidates the same-origin pointer at least every 60 seconds while visible and
before rendering after resume; a failed revalidation at the 60-second deadline makes
lookups unavailable. A changed pointer invalidates the session's rendered results
and in-flight work. A new session verifies the replacement in full. It never patches
old results with individual replacement shards. A browser cannot learn withdrawal
before a changed pointer is published; the 60-second bound starts at publication.

The build scheduler runs at least hourly; refresh work must start at least 24 hours
before the earliest aggregate expiry. A gate failure never renews old bytes. When
eligibility is lost and no qualified replacement exists, publish an unavailable
application shell through the protected operational path; cached sessions remain
unavailable. This path cannot publish unknown or synthetic data as production facts.

## Candidate inventory and approval

Before freezing the candidate, normalize pinned Nuxt operational timestamps to
`manifest.valid_from * 1000` UTC milliseconds. The reviewed packaging transform in
`tools/release_contract/nuxt_timestamps.py` applies only to framework
`prerenderedAt` references in `/ip/**/_payload.json` and inline `__NUXT_DATA__`, and
the `timestamp` field in the exact `_nuxt/builds/latest.json` and build-meta schemas.
The public build ID is derived deterministically from frontend source/config/lock
bytes. The transform preserves other JSON tokens, escaping and line endings; a
timestamp index shared with another state/fact field is rejected for review.

This normalization occurs before inline-script CSP hashes, output scanning and the
candidate digest. It is idempotent and permits identical frontend/release inputs to
produce identical deploy trees despite different invocation wall clocks. Upstream
publication clocks, subscription item clocks, release `valid_from`/`valid_until`,
VIA3 bytes and expiry decisions are untouched. A framework generation timestamp
cannot establish source freshness or renew any release. Never apply this transform
after preview/approval: production still promotes the exact frozen artifact.

Freeze the entire tree before preview. Its digest is SHA-256 of canonical JSON v1
containing entries `{path,bytes,sha256}` for every physical file, sorted by UTF-8 path
bytes. Paths are relative ASCII POSIX paths with no empty/dot/dot-dot/hidden segment,
percent escape, colon or backslash. Symlinks are rejected. Digest inputs include the
frontend, control files, current pointer, all retained manifests and every object.
There is no digest file inside the tree; approvals and reports remain outside it.
Changing HTML, `_headers`, `_redirects` or a single byte after preview changes the
candidate digest. `tree_inventory` implements this independent contract.

Reject `file_count >= 18500`, `asset_bytes >= 24*1024*1024`, and a generated tree
above 3072 MiB. Count control and frontend files and both retained generations.
Every referenced object must exist and hash correctly; unreferenced database
objects, private catalogs/samples, source maps and audit files are forbidden.
The binary scanner must decode every VIA3 section with the bounded reader and
inspect every dictionary value; raw-byte grep cannot certify compressed data.
`tools/release_contract/prepare_static.py` invokes the Go reader's bounded NDJSON
inspection, scans every dictionary string, verifies the full immutable atlas, and
copies it into the generated Nuxt tree. It then hashes exact executable inline
script bodies into `_headers` and scans frontend bytes against private catalog
identities, including escaped/base64/percent-encoded literals. Inert JSON hydration
is scanned but needs no executable-script CSP exception. Software implementation
tokens and mandatory OSM attribution are not treated as IP source metadata. The
synthetic packaging command is:

```powershell
python tools/release_contract/prepare_static.py --atlas build-private/synthetic-atlas --public web/.output/public
```

It hard-rejects production mode until production capability/approval/report gates
exist. Its source-free local report is `reports/static-candidate.json`; only a
passing exact digest may be supplied to preview. No report is stored in the tree.

Approval schema v3 remains default-deny. It binds `source_catalog_sha256`,
`rights_audit_sha256`, `release_manifest_sha256`, `candidate_bundle_sha256`,
`evidence_sha256`, `release_id`, named `approver` and UTC `approved_at`.
`approval_scope.release_manifest_template` resolves `{release_id}` after validating
the ID; it is never `releases/current/manifest.json`. The evidence digest covers
the private immutable acceptance packet with candidate digest, preview deployment
ID, exact revision/config hashes and every required report. `requirements: true`
is policy, not evidence. `verify_approval` checks identity binding only; it cannot
replace independent report verification, production capabilities or current rights.

No automatic production workflow exists in P0. After every required gate passes,
an explicit protected promotion rechecks source eligibility, withdrawal, expiry,
approval/evidence hashes and candidate tree digest. Promote the exact preview
artifact; never rebuild between preview and production. Read-only post-deploy
checks verify pointer/manifest hashes, actual root HTTP 302, cache/CSP headers and
the complete object inventory. Upload success alone is insufficient.

## Retention and rollback

Two generations is a maximum, not a mandate to keep unsafe data. Ship only current
and immediate previous eligible releases, deduplicating identical objects. Previous
release eligibility requires current rights, no withdrawal, supported schema and
unexpired contents; rollback additionally requires less than 48 hours since that
release's `valid_from` and its original successful hosted reports. Never restore an
expired or withdrawn release. If none qualifies, report rollback unavailable and
remain fail closed. Retain the eligible prior artifact until replacement validation
finishes within this bound; do not extend expiry to create a rollback.

Private approved snapshots/normalized evidence have a maximum 168-hour rollback
retention after removal, shortened by rights withdrawal and source expiry. Delete
expired input snapshots and derived output immediately from eligible build state;
retention is isolated audit storage, never an ingestion cache. Raw subscription
bytes remain only in controlled parsing quarantine and are deleted immediately
after parsing or failure (retention zero hours). Redacted audit decisions and hashes
may remain 30 days if rights allow. Prune unreferenced objects from subsequent trees.

## Evidence boundary

The implementation includes identity/expiry/scanner/inventory tests, synthetic
packaging and hosted workflows. Dated exact-revision results and Pages preview
evidence belong in `VALIDATION_REPORT.md`; the presence of this contract or a
workflow is not itself acceptance evidence. Synthetic previews do not establish
real-source qualification, full-capacity measurements or production approval.
The mandatory gates remain blocking until they actually pass for the frozen
candidate and its current user-approved release scope.
