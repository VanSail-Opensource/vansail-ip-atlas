# Production CI cloud handoff — 2026-11-15

Continue the full production and website release in
`VanSail-Opensource/vansail-ip-atlas`, branch `codex/production-release-v6`.
PRs #1 and #2 are merged. The user explicitly approved releasing verified data
with unavailable routing facts shown as unknown; all pages remain implemented.
Read `AGENTS.md` and `IMPLEMENTATION_PLAN.md` first. This is a checkpoint, not
a completed production release; the historical evidence below remains historical.

## Approved decisions

- Retain all views and all twelve detection categories. Use versioned observed
  risk with explicit incomplete coverage; absent evidence never means safe.
- Automatic exact-candidate gated publishing on official GitHub-hosted runners.
- Existing public repository, encrypted private-state artifacts, no companion
  private repository and no manual per-candidate approval gate.
- Required reviewed local publisher logos are permitted in the global credits.
- CC BY-SA 4.0 compiled data, independent source rights/freshness certification,
  correct BGP/Tier-1 semantics and original resource/performance limits remain.

## Implemented

- Public schema 4, observed-risk arithmetic, confidence/coverage, IPv6 behavior,
  /24 scored-cell mean/denominator, Go/TypeScript parity and UI labels.
- Production stages: authenticated intake, frozen candidate, fifteen parallel benchmark
  cases, completed benchmark join, preview and promotion; a checked dispatch relay
  resets GitHub’s three-level workflow-run chain;
  official Ubuntu runners, encrypted age checkpoints, trusted exact-head checks,
  measured resource envelopes, automatic authorization and eligible-only rollback.
- Release catalog contains ten statically admitted entries, including dated Tor
  exits and Ipverse ASN usage. Four unqualified routing candidates are excluded.
- Credit document version 2, locally hashed PNG logos, Go/Python/TS hostile-logo
  fixtures, complete inventory binding, legal checks before lookup/Class C facts.
- Native `benchmark-state`, `corpus` and `memory-profile` commands. Engineering
  mutation copies cannot be published or issue production receipts.
- Actual valid worker stress fixtures reach 32 MiB decoded object, 96 MiB live
  decoded data, 8 MiB serialized answer and 8 MiB decoder window. Independent
  Python verification binds actual objects/answers to reported bounds.

## Live GitHub setup already completed

Repository secrets `CLOUDFLARE_API_TOKEN` and `ATLAS_STATE_AGE_IDENTITY` exist.
Variables `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_PAGES_PROJECT` and
`ATLAS_STATE_AGE_RECIPIENT` exist. Never request, print or commit their secrets.
Cloudflare token access to the intended Pages project was verified.

Environments `atlas-private-build`, `atlas-preview`, `atlas-production` allow
protected branches without manual reviewer gates. Workflows independently require
main. Main requires PRs and successful `contracts`, `source-intake`,
`bundled-codec`, `synthetic-browser` checks; admins are included, approving-review
count is zero, linear history and conversation resolution are required.

## Evidence at checkpoint

- Strict config validator passes: 14 catalog entries, 10 statically active.
  A static report has no authenticated current runtime population.
- Ten observed catalog fixtures pass against the final internal implementation
  hash. Local private full Tor and Ipverse captures also parsed successfully.
- Local `go test ./...` passed all compiler, reader, admission and command packages
  but failed optional `tools/source_samples/TestPrivateSampleInventory`: this
  Windows workspace retains an ignored historical 91-source reconnaissance
  manifest, which differs from the current 14-source catalog. Those private raw
  captures are not in Git and must not be uploaded to satisfy a test.
- Full Python discovery: 132 tests passed before the final two memory-verifier
  tests were added; those two focused tests passed separately.
- Eight browser legal-asset module tests, 45 worker parity/security cases,
  thirteen scoring vectors and focused command regressions passed locally.
- Actual age encryption/decryption, wrong-key and truncation regressions passed.
  Actionlint passed. The large 200,005-prefix compiler regression passed locally
  in approximately 171–185 seconds; this is not the production performance gate.
- Local frontend typecheck passed using the installed CLI, with local Node 24
  unsupported-version warnings. Official CI pins Go 1.27.4, Node 26.13.1 and
  pnpm 11.28.12. Hosted stable Chrome/cgroup and exact-commit CI remain pending.

## Codex Cloud continuation — 2026-11-15

- Restored the ASN-usage fixture's exact certified CRLF bytes and disabled Git
  text conversion for observed JSON fixtures. Strict validation now passes on
  Linux without changing the recorded payload hash.
- Both readers reject scored `/24` cells without supported reasons, including
  rounded-zero scores. Shared hostile fixtures cover both cases; the all-families
  compiler fixture now supplies consistent positive evidence. Observed parser
  certifications were refreshed only after actual fixture reruns.
- Runner and Chrome scopes share an aggregate limited systemd slice. Pinned
  executable paths survive sudo; disk accounting includes active toolchains,
  Chrome, workspace caches and temporary files without counting hardlinks twice.
  Checkpoint restore and packing also run inside the resource envelope.
- CI discovers all hosted Python regressions. The complete 200,005-prefix
  capacity test remains in `go test ./...`; selected race tests exclude only
  that capacity test, whose instrumented run exceeded Go's ten-minute timeout.
  The remaining pipeline race regressions retain external sorting, resource
  guards, cancellation, cross-partition context and withdrawal coverage.
- Local full Go tests/vet, seven fuzz targets, strict contracts, 132 Python
  contract tests, 35 hosted Python tests, actual age roundtrip/wrong-key/corruption
  tests, frontend typecheck and 217 Node/TypeScript tests passed. Chrome passed
  21 synthetic UI scenarios and all three actual worker boundary workloads.
- Local synthetic LCP p95 was 2.904 seconds against the unchanged 2.5-second
  ceiling during concurrent validation; other measured local comparisons passed.
  Local intake could not reach upstream data. Use the PR's exact-commit hosted
  checks for intake, browser timing and systemd memory evidence; these local
  results do not establish production acceptance.
- Official hosted run 43678756537 subsequently passed full current intake for
  all ten active sources, contracts, codec and synthetic UI/timing checks. Its
  maximum-profile Chrome process tree exceeded the unchanged 384 MiB ceiling.
  Run 43681804844 completed the 8 MiB answer and repeated lookup, then hit the
  same ceiling while loading the 96 MiB live-decoded case. Required exact-head
  checks on PR #1 remain authoritative; these earlier runs do not authorize merge.
- Run 43682513705 passed contracts, codec and all ten current source intakes.
  Its Chrome workload completed every case and repeat without an OOM, but its
  raw peak reached exactly 384 MiB and correctly failed the strict ceiling.
- Browser allocation fixes preserve every route, serialized answer and profile
  boundary: fixed-size XXH64 arithmetic, exact bounded answer-size counting,
  bounded sharing of identical path segments, and explicit release of owned
  decoded/compressed buffers after their final use. Streamed decoder blocks are
  released only after their history copy; checksum and actual-output guards stay
  intact. The harness uses bounded encoding scratch and disables only Chrome
  background services, retaining complete process-tree accounting from birth.
- The combined emitted worker passed all three local maximum-profile cases and
  repeats, including the retained 8 MiB answer. Local sampled peak PSS decreased
  from approximately 569 MiB to 480 MiB; PSS is diagnostic and cannot substitute
  for the official cgroup peak. CI runs this memory gate before the longer UI and
  timing suite so a failed maximum workload produces evidence promptly.
- Subsequent prefix validation uses offsets to avoid millions of temporary
  array views. The frozen pnpm lock now also binds a small ESM/CommonJS patch to
  fzstd 0.1.1 that releases private scratch/history buffers after their final use;
  upstream registry integrity and the MIT notice remain unchanged. Independent
  original-versus-patched parity checks, all thirty maximum-profile sections,
  split/concatenated streams and the exact emitted bundle license audit passed.
  The final local profile retains every boundary and answer, with sampled PSS
  approximately 467 MiB. Bounded source-free cgroup sampling aids diagnosis;
  acceptance still uses the unchanged raw peak from Chrome process birth.
- Run 43683638898 again completed all memory cases without an OOM but reached
  the strict ceiling. Its sampled peak occurred during the repeated 96 MiB
  lookup. Worker SHA-256 now uses pinned `@noble/hashes` 2.0.1 to avoid WebCrypto's
  input-sized snapshot copy; digests, async API and integrity checks are unchanged.
  Independent native-reference comparisons and the exact MIT notice/runtime audit
  pass. The emitted local workload peak fell another approximately 24 MiB, to
  444 MiB PSS. The maximum workload slowed from approximately 3.8 to 7.5 seconds;
  this measured CPU/memory tradeoff still requires exact-head hosted acceptance.

## Post-merge verification and clock repair

PR #1 merged as `2fb38d95fd762c9421be40340507e014bbe67199`. Required PR and
exact-main checks passed; main Chrome peaked at 382.13 MiB with no limit/OOM
events. Authenticated intake run 43686153011 retained all ten active sources,
encrypted and uploaded its checkpoint, and removed plaintext state. The candidate
restored that checkpoint successfully but exposed an orchestration clock mismatch:
compilation requires the sealed intake's evaluation time, not the later job time.

The follow-up repair reads the bounded restored state clock only for compilation,
then immediately verifies production eligibility at current time before corpus
generation or packaging. Invalid/future clocks and current-time verification
failures stop the stage. Source intake now runs alongside the other independent
integration jobs; all four checks still have to pass before production proceeds.
The earlier candidate failure must not be described as a demonstrated
routing-qualification rejection.

The four routing-source qualifications below remain unresolved. No production
release or publisher permission is implied by these implementation fixes.

## Full website release continuation — scope v6

The user requested resolving/removing failed feeds and completing production and
website release, then explicitly selected “Release verified data with explicit
unknowns.” After the current release work, the user additionally requires
researching and qualifying replacement sources, then verifying that production
and the website are fully available. Do not stop at a merged PR or a partial
implementation. Preserve honest unknowns until each replacement has real rights,
publication, parser and full-payload evidence. Four unqualified routing entries are removed from the catalog; ten
reviewed active sources remain. Routing availability is still computed and bound,
but missing origins/paths/relationships/RPKI/Tier-1 yield unknowns. Core source
capabilities, every included-source rights/freshness check, exact-artifact gates,
resource ceilings and current-time verification remain mandatory.

The latest v5 main integration passed. Its later authenticated intake failed with
6/10 active sources current and four `publication_metadata_unavailable` results;
plaintext cleanup succeeded and all downstream stages skipped. Source acquisition
had ignored the configured GitHub token and did not retry rate-limit 403 responses.
The repair uses a dedicated token only on canonical GitHub metadata URLs, strips
it on every redirect, and honors bounded retry deadlines without changing proof
or age validation. The previous public aggregate cannot identify the four feeds
or prove a particular HTTP failure.

Scope v6 also binds real corpus availability, tests unknown views, retains all
real browser viewport/theme populations and separate synthetic graph/worker
capacity evidence, and adds an actual private compile/native-lookup integration
check before merge. Production stage logs expose only fixed phase labels.
Unchanged-input materialization reuse and native reader improvements must be
validated against the original performance limits; local improvements are not
hosted or production acceptance.

Local v6 validation passed full Go tests (including the 200,005-prefix case),
Go vet, 136 Python contract tests, 218 Node/TypeScript tests, typecheck/generate,
21 UI scenarios, standalone graph export, and the 585-package runtime license
audit. All ten observed parser fixtures passed after code-bound certification
refresh. The final 104 accessibility states had zero violations, incompletes or
runtime errors. Local mobile graph measurements met the unchanged gate in all
three ten-second phases. Hosted actual-data capacity and release gates remain
pending; these local results do not authorize production.

PR #3 is open on this branch. At head
`324da7339e10d4db7cd5238f1d66296020cb4af9`, hosted run `43697685335`
passed contracts, codec and synthetic browser checks. All ten reviewed inputs
passed actual intake, but `compile-production` reached its unchanged 35-minute
deadline before corpus or native lookup measurement. No memory/disk limit or
OOM event was reported. The source-free evidence artifact `14157315239` was
verified against SHA-256
`2c2877b000f3a38f5d94739f1d4e39bc1fbaf7dbdb269796f80c49834e6f0f3a`.
The PR remains unmerged. Repeated semantic source scans are being optimized
without removing independent byte/authentication or current-time checks.
The integration driver now retains failed-compile elapsed time and accepts only
bounded, fixed-schema compiler phase diagnostics; raw child output stays private.
Optional `ATLAS_COMPILE_COUNTERS` snapshots report nine aggregate numeric work
counters at sort, merge, classify, partition and publication boundaries, including
failed stages. Their `objects_by_kind` array has exactly fourteen entries for
VIA3 kinds 1–14, including the shared label dictionary (kind 14); ASN aggregates
and prefix pages both count as kind 8. Counts come from the current object
registry, total at most 18,499, and carry no object paths or source identifiers.
The driver accepts only this closed bounded schema. These observations never
approve a candidate or relax a release gate.

The follow-up uses process-local verified-state and qualification handles to
reduce fourteen full normalized semantic scans outside materialization to three.
Every reused boundary still authenticates the actual objects, state, seal and
key; compile controls, rights, deadlines, fixtures and exact archived bindings
are rechecked. Initial semantic validation and independent current-time
verification remain strict. Tier-1 failure history ordering is preserved.
Independent review, focused race tests, full Go tests/vet, 136 contract tests
and 44 hosted-workflow tests passed. All ten observed fixtures were rerun and
recertified against implementation hash
`239240293b7acfadaccaf703d0cbd07a83caf8c091e63523bf7edfc4b598f7e5`.
At head `53a226cdf1f298adecaa18ae697b044b18b873f3`, hosted run
`43703177504` passed contracts, codec, synthetic browser and full current intake
for all ten inputs. The semantic-scan repair reduced initial Tier-1 validation
to 181 seconds, qualification to 96 seconds and the authenticated build boundary
to 1.3 seconds. The build then consumed 1,822 seconds and again reached the
unchanged 35-minute compilation deadline. Corpus and native lookup measurements
were not reached. Peak compiler RSS was 367,759,360 bytes, workspace size was
2,253,357,056 bytes, and no memory/disk/OOM events occurred. The source-free
artifact `14158672243` was independently verified against SHA-256
`801e6588e3b9d316a80851570177454f6ff358b600aee5d9f3509aa30f5ed694`.
The synthetic browser again passed 21 UI scenarios and all maximum workloads,
with a 382.40234375 MiB Chrome peak. This is not a production deployment.

The follow-up replaces intermediate streaming JSON copies with direct bounded
decoding while preserving the prior strict/v1 semantics. It skips the exact-IP
ASN prepass only when the authenticated origin index is empty, retains final
IP risk and `/24` work, and amortizes normalized spatial partition rewrites with
at most sixteen writers. Logical binary groups still choose the original first
fitting scopes. Public runs retain exact size totals and use bounded two-pass
partitioning only for strongly oversized runs; unchanged unary branches reuse
their owned run. Every final leaf still performs strict frame and binary checks.
Independent review and focused regressions cover exact public-byte parity,
inherited IPv4/IPv6 rows, count/byte bounds, shared-file GC, input mutation,
cancellation and ownership-safe cleanup. No public schema or limit changed.

The final synthetic normalized benchmark processed 400,200 records in 39.668
seconds versus 85.379 seconds before these changes. It emitted the same 602,000
unique public records, 49 partitions and 1,745,029 bytes. Compiler scratch was
428,096,930 bytes and measured process RSS peaked at 270,802,944 bytes. A larger
1,600,800-record diagnostic, measured before the final unary optimization,
completed in 162.139 seconds with 1,712,430,208 scratch bytes. These population-
specific figures do not establish actual cold/changed-input or disk acceptance.

Aggregate phase diagnostics now distinguish seeding, path reduction, ASN risk,
spatial/ASN materialization and the five public pipeline phases. The integration
report also records optional source-free normalized record/byte totals bound to
the exact successful intake state. Native lookup diagnostics report object reads
and fixed-stratum percentiles from the same original 100,000 timed samples.
No raw input, source identity or query text is exposed. All ten observed parser
fixtures were rerun and recertified at `2026-11-15T11:43:06Z` against
`a03db63ff34710e0609368326634ca918bcf58130396d0e3b7f5bf39edf20053`.
Full local Go tests/vet, selected internal and command race tests, 136 Python
contract tests, 49 hosted-workflow tests and strict schemas pass. Frontend assets
are unchanged from the previously verified v6 build. The next exact-head hosted
actual-data measurement remains required before merge. The production website
is still unreleased.

Downstream preflight found a deterministic accessibility-report mismatch before
the full production browser run: component rows omitted the axe engine identity
required by acceptance. The shared browser audit now retains the actual axe
result's engine/version for both populations, with unchanged WCAG checks and
finding counts. A regression executes the same browser callback and passes its
output into all eight Python accessibility gates; missing identity, violations
and incomplete audits still block. All 220 Node tests, eleven focused acceptance
tests and actionlint pass. The harness-only repair changes no product assets or
internal Go bytes and does not require a new parser certification. It supersedes
the in-progress checks for `9d3692149a6d5571a67ac19f955236f47941dea4`;
the final exact-head workflow must complete before merge.

## Actual scratch failure and bounded private-run repair

At `34ebd97fae5129c2c64ddb2c7a582baddc549b9e`, official integration run
`43711248505` passed contracts, codec, synthetic browser and all ten current
source intakes. The actual compiler failed its unchanged scratch ceiling after
875,598 ms during spatial materialization/public sorting. Its authenticated input
contained 22,176,484 normalized records across 228 partition references,
5,766,429,684 decoded bytes and 210,314,132 stored bytes. Source-free artifact
`14161407886` was verified against SHA-256
`d55a711215fe32153acfc304fd96c15f34445c30df6d3337d90880b53e853b4f`.
The runner reported 12,424,257,536 workspace bytes and an 8-GiB cgroup peak with
1,174 memory-max events and no OOM/kill. That cgroup value includes file cache;
it is not a measured compiler RSS. No corpus/native lookup result was reached.
The exact-head browser passed 21 scenarios, LCP p95 2,100 ms and a raw Chrome
process-tree peak of 401,555,456 bytes with no memory events.

The repair compresses every private public-record run into independent bounded
1-MiB Zstandard segments. Exact lengths, window/content size, CRC, decoded SHA,
frame extent and a terminal marker reject corruption, bombs, truncation and
trailing bytes before records escape. All physical framing/compressed bytes are
charged before writing; failures release only owned files and codec buffers.
Sparse private JSON omits only nil union fields and preserves the original dense
logical record/sort/partition limits. Format markers and raw bytes remain part of
conflict detection and scatter integrity checks. Public VIA3 bytes, fields,
partition decisions and all performance thresholds are unchanged.

The combined 400,200-normalized-record synthetic diagnostic completed in 35.065
seconds (previous 39.668), with 6,527,933 peak scratch bytes (previous 428,096,930)
and 207,192,064 measured process RSS bytes. Its 602,000 unique public records,
49 partitions and 1,745,029 output bytes were identical. This single diagnostic
is not full-production acceptance. Golden parity covers all twelve public fact
kinds, exact record/sort/partition boundaries and complete inventory/answers;
hostile tests cover sparse markers, mixed codecs, byte conflicts, malformed
compressed frames, incompressible storage, cancellation and scratch rejection.

Benchmark setup now uses the same exclusive writer lock and process-local
verified-state sequence as production, saving two redundant semantic walks.
Transformed clones, later clocks, independent fresh verification, engineering
mode, workload populations, timers and gates remain unchanged. Local fixture
reruns completed before the ten adapter certificates were refreshed at
`2026-11-15T12:41:46Z` against internal implementation hash
`32066d89907f8085c5c77b80a3240c23495763019ad4d443b9024cd6e0e58c0e`.
Full local Go tests/vet, selected internal/source-sample race tests, command
regressions, 136 Python contract tests, 49 hosted-workflow tests, strict schemas
and actionlint pass. The production website is still unreleased; the next
exact-head actual-data measurement must pass before merge and all downstream
production stages.

The user now explicitly requests replacement-source work in parallel with the
release repair. Research includes complete RouteViews MRT capture and IPtoASN
mapping qualification. Neither is activated: source rights/notices, item clocks,
actual acquisition and faithful mapping-versus-announcement semantics require
separate proof. Research captures remain ignored and private. Do not contact
publishers or count mirrors as independent routing evidence.

## Current actual-data result and parallel replacement integration

Official integration run `43715534541` at
`add8fb613b569b89d90b74c59dfec76164eb0f35` passed contracts, codec,
synthetic browser and complete intake for all ten sources. It failed the
unchanged 35-minute compiler deadline at the beginning of public merge.
Spatial materialization took 1,710,873 ms, seeding 135,920 ms, Tier-1 setup
151,616 ms and qualification 79,318 ms. The 22,176,484-record input is unchanged
in size. Compression repaired the earlier resource failure: peak workspace was
2,432,974,848 bytes, the runner cgroup peaked at 713,973,760 bytes, and all
memory-limit/OOM event counts were zero. This does not establish compiler RSS.
Source-free artifact `14163712287` was independently verified against SHA-256
`515d3c4c1c77e5b5c0cee71518fa1623a5e676d1759ed62123d4b4122f708fc7`.
No actual corpus/native lookup or production acceptance was reached. PR #3
remains unmerged and the production website remains unreleased.

The user subsequently authorized educational source use despite redistribution
compatibility limits. This supersedes the older compatible-redistribution-only
restriction below. Record the exact per-source educational-use decision and
actual upstream terms; do not invent a publisher grant or omit notices. It does
not authorize bypassing authentication, changing facts or removing resource gates.
The user also explicitly accepted expired RPKI authorizations remaining visible.
Retain their authentic snapshot observation and authorization-expiry clocks and
label them as snapshot results. Do not revert to hiding expired results or using
one imminent authorization expiry to disable the whole website. Other source
publication/item freshness controls remain unchanged.

Parallel integration lives in `/tmp/vansail-educational-sources`, branch
`codex/educational-source-qualification`, separately from this frozen release
repair. It includes educational decisions/notices, original publisher PNG logos,
unsupported MRT-origin boundaries, a strict FFraud adapter, complete historical
RPKI proof version 2, public schema 5 with per-result clocks, and the website's
snapshot display. Its explicit observed RPKI excerpt never grants runtime
completeness; original full metadata counts and row values are preserved.
The schema-5 website passed 231 Node tests, typecheck/generate, 22 emitted-browser
scenarios, and eight viewport/theme accessibility checks locally. These are not
hosted production acceptance. CAIDA monthly discovery/embedded topology dates and
WIDE/RRC18 complete-RIB rotation are being integrated independently. All new
sources still need final exact-code certification, actual intake and production
capacity gates before inclusion. No publisher contact occurred.

The compiler now encodes closed private run metadata without repeated JSON
reflection and reuses owned canonical record frames during materialization.
Every input walk retains chunk integrity, strict JSON decoding and semantic
validation. Actual logical byte limits and legacy imported-record behavior remain.
The combined local 400,200-record diagnostic took 24.797 seconds, versus 35.065
seconds before these changes, with identical 602,000 public records, 49 partitions
and 1,745,029 output bytes. This is not actual hosted capacity acceptance.

All fifteen original production benchmark cases now run in separate hosted jobs.
A checked dispatch relay resets GitHub's workflow-run depth; a completed-run join
independently binds all fifteen successful jobs and digest-verified artifacts to
the exact candidate, configuration, state and original limits. Preview and
promotion independently verify the joined evidence and original frozen candidate.
No runtime, workload, resource or lookup gate changed.

On the parallel ten-source release branch, observed parser fixtures were rerun
and recertified at `2026-11-15T14:07:02Z` against internal implementation hash
`63d9ddf18af054428cd1feb45e08ca8bbd170da0889859373cbf2f5fc203029f`.
The next exact-head hosted run must still compile the actual full inputs and pass
the individual 100,000-lookup p95 ceiling before merge. Separate work is reducing
repeated verified Tier-1 discovery scans for the unchanged-build runtime gate.

## Replacement intake integration prepared — 2026-11-15

The isolated source branch merges the root checkpoint `27edf82`, including
performance/orchestration through `6b1c617`, and the authenticated Tier-1
verification fusion `3b439fe`. Native ASN prefix pages also reuse bounded
canonical prefix text from `cb14b68` within the original cache/live budgets;
optional text is reclaimed before required payload space. Semantic review retained
schema-5 RPKI observation/coverage clocks, every original VRP,
exact private-run logical byte budgets and schema-4 cache rejection. The fifteen
original build benchmark cases remain required under the completed-run matrix.

All five reviewed replacements are now `active` for attempted intake: FFraud,
RouteViews WIDE, RIS RRC18, CAIDA serial-2 and rpki-client. The closed MRT controls
enable exactly WIDE/RRC18, retaining two independent families and the unchanged
1-GiB shared compressed ceiling. Publisher terms, exact notices/logos and the
explicit educational-use decision remain recorded. No static activation grants
permission, produces a runtime receipt or certifies current coverage.

All fifteen exact observed fixtures were parsed and semantically validated before
the certification ledger was refreshed at `2026-11-15T14:22:58Z`, then rerun
successfully. The ledger binds internal implementation hash
`996f229b77a7e09d4cd12a8404fbd9291209ddc638b1fbc8985d98cac092ddc6`.
Any later internal Go edit requires another observed-fixture run and refresh.
Local strict schemas, 157 Python contract tests, the full Go suite and vet,
selected internal/source-sample races, focused source/schema/cache and
maximum-memory-profile tests, and actionlint pass. All 72 hosted-helper tests pass
using pinned age 1.3.0, including real encryption,
wrong-key and corrupt-ciphertext rejection. This suite caught and repaired a
stale schema-4 object check in the memory verifier, without changing its workload,
framing checks or limits.

No catalog or observed-fixture activation blocker remains. Actual hosted intake
must still fetch and authenticate every complete current payload under the
unchanged source/stream limits. The larger admitted corpus has no measured cold,
changed-input, native lookup or browser acceptance result yet. No historical
Tier-1 stability is fabricated; unavailable observations remain unknown. The
website is still unreleased, and this local checkpoint does not authorize it.

## Actual replacement intake and remaining compiler failures

Official run `43724330098` at `60e78426e4c2d2a8f2d5650e3d4c1d382fd636b5`
successfully fetched, parsed and authenticated all fifteen complete current
inputs. Contracts, codec and synthetic browser checks passed. Compilation failed
the unchanged global 18,499-object cap after 2,049,148 ms; this is not a source
qualification or timeout failure. The input contained 36,455,534 normalized
records, 374 partition references, 11,154,103,519 decoded bytes and 342,160,207
stored bytes. Source-free artifact `14167084798` was independently verified
against SHA-256
`d02be13489d7b7157650bb5cfefc7e6326642004f2c01443933ba99feefdd830`.
The cgroup peaked at 1,272,410,112 bytes, workspace at 3,105,173,504 bytes, with
zero memory-limit/OOM events. No actual lookup measurement or production
acceptance was reached. The browser passed all 22 scenarios, including visible
expired RPKI snapshots, with a 402,399,232-byte Chrome process-tree peak and no
memory events. Synthetic success does not certify the actual production corpus.

The parallel ten-source run `43722878012` at `27edf82599f7bb282ddfd90a53ca63d89305ac73`
also passed complete intake and the other three integration jobs. Its compiler
failed the original 35-minute deadline during final partitioning after
2,102,318 ms. Source-free artifact `14167101520` was verified against SHA-256
`1ba15d44aa83f45d2775a7e5e9aedc5f1d6e673707f2ad155e0c096f25ae9b07`.
Neither failed head is eligible to merge or deploy. PR #3 and dependent PR #4
remain open; no production deployment exists yet.

The next integration combines reviewed cold-build improvements, authenticated
incremental materialization and bounded fact-group partitioning. Measurements
from small synthetic inputs remain diagnostic until the complete actual corpus
passes the original cold, warm, lookup, resource and hosted deployment gates.

## November 22 combined release candidate

PR #4 targets `main` and includes the work from PR #3. The compiler now partitions
compatible facts together and composes a complete destination list for each router
boundary. Separate object groups passed the native and TypeScript lookup parity
tests, including multiple origins, expired RPKI observations and empty-origin
boundaries. The production browser checks wait for the loading panel while the
snapshot status stays visible. Incremental builds reuse content-verified spatial
and compiled partitions. The compiler also avoids repeated identical adjacent
origin mappings during private seeding while retaining every path observation.

All fifteen observed source fixtures ran before and after certification refresh
at `2026-11-22T13:49:04Z`. The current implementation hash is
`b18a84649beb86113c934828af0e88f7f82976058eafa8ffcacff4627c06de45`.
Hosted intake, actual compilation, indexed lookups and the production deployment
chain must run on the new revision. Cloudflare still reported only a preview
deployment on November 22 before this push.

## November 22 compiler and browser repairs

Run `45029545267` on PR #4 passed the contract and codec jobs. Chrome 158
reached exactly 402,653,184 bytes in the 384 MiB cgroup and recorded five
memory-limit events. All three maximum-size workloads completed. The replacement
decoder uses the bytes already produced for back-references and removes the
second history allocation. The browser also reads only the relevant shards for
auxiliary lookups. The combined local build passed 249 Node tests, 15 codec
cases, 22 browser scenarios and all three maximum-size workloads. The official
cgroup measurement must be repeated on the repaired revision.

A private engineering replay of 36,465,626 normalized records exposed a second
failure in the previous candidate. ASN-risk partitioning exhausted the allowance
of 16,384 private files. The compiler now sizes top-level scatter groups against
remaining file slots and coalesces deeper groups into one stream per terminal.
A regression retained 16,640 distinct observations in 256 files. Build-local
verification of sorted intermediate runs and batched verification of imported
spatial files also reduce repeated work. Final decoding, integrity checks and
the existing file and byte limits still apply.

PR #3 carries the combined fifteen-source repair. Its fifteen observed parser
fixtures were rerun at `2026-11-22T14:15:49Z` and bind implementation digest
`7ed1c791c1d2778326b8b7d283a09f7f651d31f8057f33b0ce24b3f1575f4c83`.
Use the complete hosted run for release evidence. The private replay has no
production intake receipts or authorization to deploy.

## November 22 source and compiler follow-up

The earlier fifteen-source run `45029545267` admitted all fifteen current
sources. Its 36,478,173 normalized records occupied 374 partitions. It failed
in ASN-risk materialization after 913,207 ms overall. The source-free artifact
`14757933457` has SHA-256
`c22032708e32beb106f936d168ec105edc35d4708c9ae39ac45032f627c54605`.
The succeeding PR #3 browser run `45031970312` passed all three workloads at
396,812,288 bytes on Chrome 158. Its timer and resume checks both preserved the
expired RPKI observation. At this checkpoint the actual-data job on that run
had completed intake and was compiling.

PR #4 now includes a sixteenth source for explicit community reports of
phishing at literal IP addresses. The weekly CSV and the publisher manifest
with publication time, byte count, row count and digest must agree. The
publisher's static CDN served the preceding edition during verification. The
manifest's listed original file matched all 307,265 bytes and 2,408 rows of
the newer edition, including 40 qualifying reports on 37 distinct addresses.

The compiler verifies source record predicates during the authenticated input
traversal. It packs multiple logical ASN prefix pages into each physical
object and keeps the original page cursors. On 1,371,704 observed prefixes,
the packed layout reduced the prefix object count from 5,404 to 2,004 with
identical returned prefix sequences. It also drops location values that
repeat their inherited value. An engineering sample of 49,152 geographic
records produced 35,474 location rows, down from 119,277. All 93,162 sampled
starts, ends and adjacent addresses returned identical values for geography,
coordinates and usage. Network and announcement prefixes retain their identity.
The complete actual corpus and hosted release gates still govern promotion.

All sixteen observed fixtures passed against implementation digest
`1e2276a77af661f3613360ac02d3e980a93dce96ee9581b262152c23f883335d`
at `2026-11-22T14:44:42Z`.

## November 22 production candidate with seventeen sources

The draft release branch includes the IANA root-server service addresses in
addition to the sixteen-source catalog. All 26 exact addresses returned true
for anycast in the offline qualification. All 52 immediate neighbors returned
unknown. The full seventeen observed parser fixtures passed at
`2026-11-22T15:05:55Z` against implementation
`83c1907ccd2cb1dd7e3f9e7216109edd6db0f7523216ea86a6ba63beebfb6091`.

The previous fifteen-source hosted run
[45031970312](https://github.com/VanSail-Opensource/vansail-ip-atlas/actions/runs/45031970312)
completed contracts, codec and current Chrome checks. Its actual-data job
admitted 36,478,172 rows and exhausted its 35-minute limit during output
partitioning. The new candidate folds complete matching location siblings,
represents complete quality subnets with a verified default and overrides,
and verifies the identities of compiler-created intermediate partitions.
An engineering replay of the complete earlier corpus with the quality changes
produced 5,888 objects totaling 119,479,954 bytes. This replay does not prove
that the official current candidate fits the deadline.

## Resume next

1. Verify the branch and clean checkout. Run strict schemas, Go tests/vet, Python
   suites, TypeScript/browser unit tests and actionlint as needed. Refresh parser
   certifications only after actual observed fixture reruns if internal Go bytes
   change; hashes bind LF-normalized `internal/**/*.go`, including tests.
2. Open or continue the PR and run the complete official hosted integration.
   Diagnose real failures; do not raise thresholds or replace measured gates
   with booleans. The synthetic-browser job now runs the actual Chrome process
   tree memory test even while real production routing remains blocked.
3. Review Linux cgroup, tool/cache accounting, checkpoint transport, runtime
   source intake and all automatic stage transitions. Checkpoints carry no raw
   quarantine or logs. Keep source-rich diagnostics out of public artifacts.
4. The replacement integration enables only the five reviewed replacements,
   under their recorded publisher terms and explicit educational-use decision.
   Current complete-payload/parser/publication proofs still govern inclusion;
   no publisher grant is implied. Do not contact publishers without instruction.
   Unavailable routing remains unknown; every product page remains available.
5. The real compiler reuses authenticated materializations only when state,
   clock, policy, limits, implementation and derived Tier-1 identity all match.
   Changed inputs or clock still require full materialization. All five benchmark
   scenarios use that same path. Actual real input must satisfy the original
   runtime ceilings without weakening retraction, freshness or accounting.
6. Merge only after required checks pass. Then verify exact-main CI, encrypted
   intake, complete candidate, hosted preview and production. Do not claim the
   public website released until every real qualification and hosted gate passes.

Cloud credentials belong in configured connections or GitHub Actions secrets.
No private local capture, plaintext credential or local application auth file is
needed in this branch or in the cloud handoff prompt.
