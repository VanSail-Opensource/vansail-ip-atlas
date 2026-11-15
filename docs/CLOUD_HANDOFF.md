# Production CI cloud handoff — 2026-11-15

Continue the user's implementation request in
`VanSail-Opensource/vansail-ip-atlas`, branch `codex/production-ci-v5`.
The user requested moving the ongoing work to Codex Cloud. This is a checkpoint,
not a completed production release. Read `AGENTS.md` and `IMPLEMENTATION_PLAN.md`
first. All implementation changes are saved in this branch.

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
- Shortlist reduced to fourteen sources. Ten statically admitted entries include
  dated Tor exits and Ipverse ASN usage; four routing candidates remain blocked.
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
  contract tests, 31 hosted Python tests, actual age roundtrip/wrong-key/corruption
  tests, frontend typecheck and 216 Node/TypeScript tests passed. Chrome passed
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

The four routing-source qualifications below remain unresolved. No production
release or publisher permission is implied by these implementation fixes.

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
4. Real routing qualification remains unresolved: RIPE RIS, RouteViews, CAIDA
   relationships and the RPKI snapshot need compatible reviewed rights and exact
   complete-payload/parser/publication proofs. CAIDA requires publication
   reporting; ARIN relying-party data terms are distinct from the rpki-client
   software license. Do not invent approval or contact publishers without an
   explicit user instruction. Tier-1 requires real separated authenticated epochs.
5. The warm compiler currently performs full materialization. All five benchmark
   scenarios use that same path; no benchmark-only shortcut exists. Actual real
   input may fail unchanged/changed runtime ceilings. Measure and optimize the
   real pipeline without weakening retraction, freshness or accounting.
6. Merge only after required checks pass. Then verify exact-main CI, encrypted
   intake, complete candidate, hosted preview and production. Do not claim the
   public website released until every real qualification and hosted gate passes.

Cloud credentials belong in configured connections or GitHub Actions secrets.
No private local capture, plaintext credential or local application auth file is
needed in this branch or in the cloud handoff prompt.
