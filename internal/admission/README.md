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

Before network IO, intake requires an active milestone, explicit reviewed
no-attribution rights, an implemented parser/schema/version, exact public-field
mapping, the observed real-fixture controls, and the matching reviewed ledger
entry. It verifies fixture bytes and the current sorted internal Go code hash,
then reruns that exact fixture through the current parser. This module cannot
create reviews or certifications. The checked-in ledger remains empty, all 91
catalog entries remain ineligible, and the catalog regression performs no fetch.
`CertificationFingerprint(ctx, workspace, sources)` binds the ledger, current
internal Go bytes and active fixture bytes with a 64 MiB aggregate read cap.
Compare it before and after intake alongside the configuration fingerprint, so
mid-build review withdrawal or code/fixture changes invalidate the result.

The implemented publication verifier fetches GitHub release metadata using the
same public-address-pinned HTTPS acquisition code. It requires the source and
metadata URLs to name the same repository, an exact asset download URL, uploaded
state, matching actual size and a publisher SHA-256 digest matching the locally
stream-hashed payload. The older of release publication and asset creation is
the clock. Missing digests, different assets, malformed or duplicate JSON keys,
unapproved origins, unknown/future clocks and stale content fail closed. It does
not use download time, HTTP 304 or local file timestamps as content age.

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

Runtime dispatch currently handles the explicit VRP CSV/JSON schemas. The bounded
MRT TABLE_DUMP_V2 unicast/ADDPATH fixture parser exists, but runtime intake
quarantines MRT until a dedicated coordinator enforces the global enable switch,
two independent families, sequential downloads and their shared 1 GiB budget.
Payloads may be plain, gzip or bzip2 as declared. A source partition is capped at
100,000 normalized records / 64 MiB,
with 1 MiB records and bounded existing archive/parser readers. Larger sources
are rejected, not truncated. Whole-source streaming partitions/external merge,
additional source adapters, archive-member selection, discovery, embedded clocks,
GitHub commit proofs and broader publication proof methods are future integration
work. Unrepresentable or expired MRT observations fail the partition rather than
inventing an origin or silently dropping route structure.

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
