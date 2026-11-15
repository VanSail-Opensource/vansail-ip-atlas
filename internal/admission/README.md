# Build-private source intake

`DecodeCatalog` projects the schema-validated source YAML into typed controls.
The complete five-file `tools/validate_blueprint.py` gate must run first; this
projection does not replace that closed schema validator. It independently
rejects ambiguous YAML, invalid dependency graphs, bounds and scope mismatches.

Create one `Engine` per build/workspace, defer `Close`, and reuse it for every intake so public
HTTPS acquisition shares the run-byte and concurrency budgets. `Ingest` requires
an explicit build clock and normalization-policy hash. Its private `Result`
contains the policy, runtime decision and a snapshot only on success. Every build
must pass all policies and successful snapshots to `intelligence.Reconcile`,
including when no payload changed. That step resolves dependencies and retracts
sources that are retired, stale, unavailable or no longer reviewed.

Before network IO, intake requires an active milestone, an explicit reviewed
source-use decision (`allow` or `user_authorized_educational_use`) and any required
global credits, an implemented parser/schema/version, exact public-field
mapping, the observed real-fixture controls, and the matching reviewed ledger
entry. It verifies fixture bytes and the current sorted internal Go code hash,
then reruns that exact fixture through the current parser. This module cannot
create reviews or certifications. The checked-in ledger binds reviewed observed
fixtures; active catalog entries still need fresh, hash-bound intake receipts.
The educational decision records the user's project authorization; it neither
grants publisher permission nor changes upstream terms. Unknown or denied
decisions, missing terms evidence and unresolved attribution still fail closed.
The catalog regression performs no fetch and cannot qualify production by itself.
`CertificationFingerprint(ctx, workspace, sources)` binds the ledger, current
internal Go bytes and active fixture bytes with a 64 MiB aggregate read cap.
Compare it before and after intake alongside the configuration fingerprint, so
mid-build review withdrawal or code/fixture changes invalidate the result.

The release publication verifier fetches GitHub release metadata using the
same public-address-pinned HTTPS acquisition code. It requires the source and
metadata URLs to name the same repository, an exact asset download URL, uploaded
state, matching actual size and a publisher SHA-256 digest matching the locally
stream-hashed payload. The exact asset's creation is the content clock;
release publication must also be valid but an old tag does not age a genuinely
new uploaded asset. Publishing a new tag cannot renew an old asset. The retained
earliest clock still prevents identical-byte re-upload renewal. A derived mirror
additionally needs its original upstream content clock. Missing digests, different assets, malformed or duplicate JSON keys,
unapproved origins, unknown/future clocks and stale content fail closed. It does
not use download time, HTTP 304 or local file timestamps as content age.

The commit verifier accepts only GitHub's path-filtered one-result commit query
for the exact repository/ref/file named by a raw GitHub source URL. It validates
the full immutable commit ID and repository URL, uses the older of the UTC author
and committer clocks, downloads that same file at the immutable commit, and
requires its SHA-256 and byte count to equal the original payload. A branch race,
different content, unbound path/ref, duplicate JSON, unavailable payload or invalid
clock quarantines the source. Both copies share the normal acquisition and disk
budgets and are removed with quarantine. This avoids treating a mutable branch,
repository-wide activity or Git SHA-1 blob identity as content-publication proof.
The fetcher's sole initial URL-query exception is this closed GitHub API shape:
exactly `path`, `sha` and `per_page=1`; credentials, other queries and pagination
remain rejected. See the [publisher API contract](https://docs.github.com/en/rest/commits/commits#list-commits).
The existing earliest-content-clock retention also applies to commit receipts;
recommitting known identical content cannot renew its observed publication time.

Verified clocks are also retained across runs in the fixed private
`.atlas-private/publication-clocks-v1.json` anti-replay audit. Equal content can
only retain or decrease its publication timestamp. Re-uploading identical bytes
with newer metadata therefore cannot renew a previously verified clock. The
file contains hashes and UTC timestamps only, is atomically replaced, and is
bounded at 25,000 receipts / 4 MiB. Overflow or invalid retained history fails
closed. Updating an existing hash to an earlier clock remains allowed at capacity.
It does not establish publication history from before the first verified
observation; removing it loses that history. `New` enforces an exclusive lifetime
workspace lock across processes. `Close` waits for in-flight operations and
releases only its owned lock; closed engines cannot perform IO. A stale lock
fails closed and is never automatically erased or stolen.

The dedicated `IngestMRT` coordinator is the only runtime MRT entry point. It
checks the enable switch, two reviewed independent families and their exact
parser certificates before sequential acquisition. Its shared 1 GiB physical
body-byte ceiling survives failures and repeated calls on the same engine and
also consumes the original run download budget. Complete TABLE_DUMP_V2 framing
and every common-header capture clock bind the raw payload hash to publication;
the prefix entry's older originated time is private route history, not the RIB's
publication clock. Plain/gzip/bzip2 inputs stream into bounded private record
partitions. A malformed or unrepresentable route aborts the candidate rather than
being truncated or assigned an invented origin.

The optional `download.mrt_archive_policy: latest-complete-v1` is reviewed only
for RouteViews WIDE's canonical bzip2 RIBs and RIS RRC18's canonical gzip RIBs.
The configured dated URL remains the catalog's collector/codec anchor. Intake
selects the newest scheduled slot at least 30 minutes old (two hours for WIDE,
eight hours for RRC18), with only the immediately preceding slot allowed after
a header-only HTTP 404. Other acquisition failures, invalid hashes, malformed
archives and invalid capture clocks fail the pair; they never select older
bytes. Every accepted frame clock must lie in the selected slot and at or before
the original selection time. The private sealed proof records the actual URL
and selection time alongside the full payload hash and capture clocks, so
revalidation and replay preserve the actual base without mutating the catalog
or renewing its publication age. An absent policy retains exact-URL acquisition.
This support does not enable or certify any source.

An optional `mrt_updates_fixture` has its own exact `source-id-updates` ledger
certificate for `mrt-bgp4mp-unicast-v1`. Its encoded bytes and metadata participate
in the certification/policy identity, so revocation also invalidates a retained
replay base. Without that certificate, acquisition remains a cold RIB. With it,
the coordinator may reuse an authenticated current base and derive only complete
same-collector 5-minute RIS or 15-minute RouteViews archive intervals. Explicit
archive plans obey the same checks. Names prove continuity, never freshness:
every archive is completely parsed, SHA-256 bound and checked against its frame
capture interval. No new closed interval reuses the exact sealed snapshot
without renewing its original publication age.

Replay joins a unique normalized peer-address/ASN hash from the RIB to a unique
BGP4MP transport session. Peer-table ordinals are never transport session IDs.
Missing/ambiguous peers, duplicate path keys, collector changes, interval gaps,
ADDPATH mode conflicts, unsupported restart semantics or exceeded limits fall
back to a new cold RIB within the remaining shared acquisition budget. The
transactional two-pass replay keeps only changed routes in a bounded 128 MiB
working estimate, with at most one million logical events and 180 seconds shared
across both families. It preserves exact prefixes and ADDPATH IDs, applies
withdrawals and session resets, and never publishes a partial family pair.
Full-RIB runner RSS, scratch and runtime still require actual-payload hosted
measurements; bounded synthetic tests do not certify a real source.

Subscription syntax support remains deliberately quarantined at intake: an
enclosing release timestamp cannot prove each item's publication. No subscription
download occurs until a concrete trusted per-item verifier is implemented.
`LiteralEvidence` only converts the already stripped decoder record when explicit
source and item clocks are supplied and both remain current. It does not verify
those clocks. Unknown item time never defaults to a container/fetch timestamp.

Downloaded payloads and metadata live only in generated, symlink-checked private
quarantine; success and failure remove them. Returned normalized records contain
no raw URLs, credentials, ports, protocols, labels or downloaded member names.
Cleanup failure returns an error and removes the successful snapshot from the
result, so retained raw quarantine cannot be treated as a successful intake.
The public binary layout, routes, score coefficients and Tier-1 rules are
unchanged. This module's tests are local; hosted schema qualification, race,
RSS/scratch and real-source throughput measurements have not run.
