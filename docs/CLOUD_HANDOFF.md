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
