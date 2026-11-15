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
- Four production stages: authenticated intake, candidate, preview, promotion;
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
4. Removed routing feeds remain excluded. Future reintroduction needs compatible
   reviewed rights and exact complete-payload/parser/publication proofs. Do not
   invent approval or contact publishers without explicit instruction. Unknown
   routing is approved for this release; all pages and honest unknown states stay.
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
