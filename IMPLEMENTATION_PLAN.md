# VanSail IP Atlas production implementation plan

## Current approved scope

`release-scope-v6` (2026-11-15) retains every product view, introduces versioned
observed risk, permits reviewed required local publisher logos in global credits,
and authorizes automatic gated publishing from the existing public repository on
official GitHub runners. `AGENTS.md` is normative. Earlier dated reports remain
historical evidence, not proof of current source or production qualification.

The explicit educational source-use amendment (2026-11-15) permits the reviewed
per-source decision `user_authorized_educational_use` alongside `allow`. It records
the user's project-use authorization without claiming a publisher grant or
CC BY-SA compatibility. Original compilation contributions retain their stated
license; upstream material retains its own recorded terms. Every included source
still needs terms evidence, a nonblank review basis, an explicit attribution
decision, publication proof, an observed parser fixture and required credits.
Source code and dependencies retain their separate licenses.

The explicit RPKI amendment (2026-11-15) retains expired authorization results as
publisher snapshot observations. Every original VRP is evaluated at the actual
payload-bound publisher build clock and keeps its authorization expiry. Public
schema 5 carries observed status, observation time and expiry together; the UI
keeps expired results visible with a neutral as-of/expired indication. This does
not assert current authorization or extend the snapshot's publication-based
source freshness (at most 720 hours). All non-RPKI expiry and other gates remain.
The proof/admission and schema/reader/UI halves must ship together before this
observation semantics is enabled for a production source.

## Implementation contracts

- Go ingests approved downloaded bulk files and emits deterministic VIA3 objects.
  There is no live enrichment API, probe, subscription-host DNS or server runtime.
- Nuxt 4 generates static Pages assets. Every database object belongs to the same
  frozen upload; there is no R2 or network lookup fallback.
- Root returns HTTP 302 to `/ip`. One input opens overview, quality, class-c, BGP
  and ASN routes. The quality route owns observed risk and retains its deep links.
  Each view has one canonical fact display; reserved diagnostics stay unimplemented.
- VIA3 container version 3 carries public schema 5. Go and browser readers reject
  incompatible schemas and share golden answers and hostile corruption fixtures.
- No source IDs, provenance, credentials, domains, ports, protocols, collectors,
  latency, timezone, postal or continent fields enter public facts. Only separate
  global legal artifacts contain reviewed source credits.

## Sources and freshness

The release catalog contains ten statically admitted entries. Four unqualified
routing candidates have been removed under the user-approved v6 release scope. Active is not proof of current availability. Runtime intake binds
actual bytes, certification, policy and publication clocks before inclusion.
Tor dated exits and Ipverse dated ASN categories supply observed risk and usage;
Ipverse role labels never determine Tier-1. Deprecated, stale and unqualified
lists are removed from the production catalog; useful parser regressions remain.

Any future MRT path families, directed relationships and complete RPKI snapshot
still require full qualification. A software license does not approve an upstream
dataset. `deny`, pending `review`, `unknown` and unrecognized distribution decisions block admission;
an educational exception must be explicit and retain the reviewed upstream terms.
Missing routing
coverage is explicitly unknown under v6; synthetic data or an allowlist cannot
replace it or produce real routing claims. Keep all twelve detection categories implemented, but require
available verified observations rather than twelve simultaneously active feeds.
Absent categories remain unknown.

Publication age is at most 720 hours. Retain earlier item and authorization
expiry. Downloads, mirrors and HTTP 304 cannot renew old observations. Withdrawal
or expiry retracts dependent contributions. Subscription parsing extracts only
literal public IPs, strips secrets immediately, stays bounded and deduplicates
correlated repositories as one evidence family.

## Observed risk and routing

`configs/scoring.yaml` and `docs/scoring.md` define `via-observed-risk-v1`.
Higher means more supported adverse evidence, neither probability nor safety.
Preserve signal coefficients, decay, independence, exact/prefix specificity,
ASN caps and leave-one-out neighbor calculations.

`observedRisk` has nullable score, confidence, reasons, four contributions and
explicit assessment coverage. No scored positive support yields null. Positive
support can produce a number with incomplete coverage; rounded positive zero
displays `<1`. IPv6 omits /24 influence without redistributing its weight. The
/24 mean includes only scored observed cells and exposes its denominator.

Preserve all MOAS origins and origin-specific RPKI. AS_PATH adjacency does not
establish a business relationship; conflicts and missing data yield unknown.
The graph retains actual hop semantics within 24 nodes, two protected hops and
three backbone exits per second-hop ASN. Tier-1 derives from relationships,
provider-free status, customer cone and independent visibility. Stability uses
real authenticated consecutive epochs at least 24 hours apart, never fake clocks.

## Legal assets and frozen candidates

One shared credit display contains only included real datasets' obligations.
Credit document version 2 permits reviewed bounded local hash-addressed PNGs;
the index remains version 1. Publisher links and required logos remain visible
when notices collapse. The browser verifies legal assets before exposing facts.
No remote logos or query-linked attribution are allowed.

Bind the exact data-license notice, credits, logos, application and database into
one inventory and candidate digest. Changed bytes require new evidence. Synthetic
previews have empty dataset credits; real engineering output cannot be published.

## Official hosted delivery

Integration, intake, candidate, preview and promotion use official `ubuntu-24.04`
runners, pinned toolchains and enforced resource ceilings. Keep the 2 CPU, 8 GiB
RAM and 14 GiB disk target plus stricter RSS/scratch limits in `docs/performance.md`.
A physically larger runner does not increase the allowed budget.

1. Integration runs schema, Go tests/vet/race/fuzz, source fixtures, scoring/BGP
   invariants, Go/TypeScript parity, static generation and browser regressions.
2. Trusted-main intake restores authenticated encrypted state, revalidates source
   inputs, persists real Tier-1 epochs and prunes stale data. Only an allowlisted
   age-encrypted checkpoint crosses jobs; raw secrets and lineage stay private.
3. Candidate compilation independently qualifies sources, derives benchmark
   queries from actual indexes, packages every asset and measures build/lookup
   performance before freezing the immutable tree.
4. Preview uploads that tree and runs stable Chrome regression, accessibility,
   disclosure, integrity and performance against the Pages preview URL. Synthetic
   worst-case worker profiles are engineering stress tests, not real-data proof.
5. Automatic promotion verifies protected main, exact successful upstream runs,
   current source rights/deadlines, policy, inventory and every measured gate.
   Deploy the same frozen bytes and verify live hashes, redirect and headers.

GitHub stores the age identity and Cloudflare token as encrypted secrets; account,
project and public recipient are variables. Main-only environments do not require
manual per-candidate review. Policy booleans never substitute for test evidence.

## Measurement, failure and completion

Measure three isolated cold-full, warm-changed, warm-unchanged, expiry and
withdrawal samples. Change `ceil(N/100)` actual normalized records in isolated
engineering copies and prove the deltas. Every scenario executes the same
materializer as production; no benchmark-only shortcut or production receipt.
Derive lookup strata, map and graph cases from actual current indexes. Report
p50/p95/p99, allocation counts, RSS, scratch, input size and browser metrics.
Absent routing populations are recorded and tested as unknown; they never count
as observed production data. Applicable unmeasured bounds and failed original
ceilings block release. The exact application also retains independent synthetic
24-node graph and maximum-memory capacity tests.

Keep fewer than 18,500 files and each asset below 24 MiB. Verify all object hashes,
public fields and legal assets before upload and on the hosted preview. OSM tiles
are the sole remote runtime data exception.

A failed candidate preserves the previous deployment. Rollback independently
revalidates the exact previously verified artifact against current freshness,
rights, withdrawal and bounded retention. Historical success never renews data.
Prune unreferenced objects and aged encrypted checkpoints.

Completion evidence includes modified paths, exact commit, hosted run URLs,
preview and production identity, measured benchmarks and unresolved assumptions.
Local or synthetic success is not production success. Production is complete only
when real qualification and all exact-candidate hosted gates pass and live bytes
verify. See `docs/source-policy.md`, `docs/release.md`,
`docs/production-qualification.md` and `docs/production-evidence.md` for executable
source, release and evidence contracts.
