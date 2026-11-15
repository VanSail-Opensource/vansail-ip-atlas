# Production evidence and automatic hosted delivery

The user-approved `release-scope-v6` retains CC BY-SA 4.0 compiled data and strict
source qualification. It adds schema-5 dated RPKI snapshots and observed-risk answers, verified included
publisher logos, encrypted state transfer and automatic promotion after all gates.
A pipeline or passing fixture is not evidence that a real source or release passed.

The v6 amendment explicitly permits unavailable routing facts to remain unknown.
The release retains all views and every included-source qualification check.

Production uses the current public repository and official `ubuntu-24.04` runners.
Every workload is bounded by a cgroup with 200% CPU, 8 GiB memory and no swap; all
mutable task storage is counted against a 14 GiB workspace with a 1 GiB reserve.
Raw host capacity is reported separately. No self-hosted runner or preprovisioned
private corpus/scenario workspace is required.

## Workflow and trust chain

`production-intake.yml` runs on main pushes, hourly at minute 17, and manual recovery.
It waits for successful integration on the exact protected main revision, restores
an eligible encrypted checkpoint and independently revalidates actual source intake.
A genuine Tier-1 observation is retained even when the first snapshot cannot yet
qualify production. Intake success is distinct from production capability success.

Successful intake starts candidate, preview and promotion through three successive
`workflow_run` triggers. This stays within GitHub's three-level chaining limit.
Each consumer independently verifies repository, workflow, event, branch, revision,
run completion and artifact identity. A changed main revision stops the old chain.

Integration additionally compiles actual admitted inputs privately and measures
100,000 indexed native lookups before merge. It uploads only fixed phase/status
and numeric resource/latency reports, never the actual source state, query corpus
or compiled real database. Its 90-minute job timeout accommodates intake plus the
separate original 35-minute cold-build ceiling; no performance threshold changes.

The candidate compiler creates its authenticated receipt and complete immutable
public tree. The corpus command derives 10,000 actual indexed queries and explicitly records
observed and absent strata. Missing routing populations yield tested unknown
states, not fabricated routes. Graph component capacity is measured separately
with an explicitly synthetic 24-node fixture against the exact application bytes.
The build harness derives fifteen isolated engineering cases from the exact
sealed input, instead of requiring manually prepared directories. Warm cases are
primed before measurement. Rounded one-percent mutations use `max(1,ceil(N/100))`.
Every replay output is private engineering data and is rejected by production
packaging; replay cannot approve a source or manufacture a production observation.

Preview uploads the unchanged public artifact to an immutable Pages URL and checks
every file, control header and redirect before and after actual stable-Chrome
regressions. Browser coverage remains 30 contexts for each of four widths and two
themes, complete owner-route interactions, accessibility, LCP, CLS, Event Timing,
24-node graph work, 100 cold queries and three 1,000-query hot populations.

`worker_memory.py` launches the entire Chrome tree inside a fresh cgroup from
process birth. It runs the exact emitted worker against a bounded synthetic
maximum-profile fixture through actual decoding, query and structured-clone paths.
The Chrome peak is a conservative upper bound for the worker, not a sampled heap
or an existing renderer moved into a new cgroup. OOM, missing populations or a peak
at/above 384 MiB fails. Synthetic profile correctness never supplies source coverage.

Promotion assembles the private canonical acceptance packet from successful
exact-head GitHub artifact IDs and SHA-256 digests. `configs/production-policy.json`
replaces per-candidate manual approval: protected main, a main-only production
environment, current source-store qualification and every measured gate remain
mandatory. Rights and license decisions remain reviewed code policy. The exact
catalog, rights, receipt, candidate, preview and evidence digests are bound before
unchanged bytes are promoted and reverified at the production alias.

## Encrypted checkpoints

Pinned age 1.3.0 X25519 encrypts a streamed compressed archive. GitHub immutable
artifact/run provenance authenticates the producer; age authenticates ciphertext.
The private identity is `ATLAS_STATE_AGE_IDENTITY`; only its public recipient is
stored in `ATLAS_STATE_AGE_RECIPIENT`. The main-only environments are
`atlas-private-build`, `atlas-preview` and `atlas-production`.

The closed source-free envelope binds version, kind, repository, revision, run and
attempt, creation/expiry, key ID, ciphertext size and SHA-256. An allowlist admits
normalized partitions, original seals/key, publication clocks, authentic Tier-1
history, receipts and the private corpus. Raw subscription bytes, intake quarantine,
locks, scratch and child logs are excluded. Decryption finishes authentication
before bounded regular-file extraction; links, traversal, duplicates and unexpected
paths fail. Old captures never gain a new upstream publication time on restore.

Ciphertext expires no later than the earliest current source deadline or 168 hours.
A source-free index permits automated deletion of expired ciphertext without
fetching bulk private contents. Seven-day GitHub retention is an upper bound;
older redundant checkpoints are pruned. Missing or expired state causes a clean
intake and genuine history warm-up, never invented stability.

Public artifacts contain only source-free reports, ciphertext and already-scanned
public bytes. Child diagnostics stay local; plaintext state is removed after each
job. Cloudflare credentials are used only by preview/promotion. No runtime website
API, external database fallback or upstream lookup is introduced.

## Rollback and evidence boundary

If a known new production deployment fails postchecks, rollback independently
restores the last successful encrypted production checkpoint and exact public
artifact, then reruns current rights, expiry, original hosted evidence and the
48-hour eligibility check. Missing or unsafe rollback state cannot authorize a
restore. The attempted release still fails even when eligible rollback succeeds.

Cron is best effort and public-repository inactivity can disable schedules; manual
dispatch is the recovery entrypoint. The static client continues to reject expired
facts. Exact-head hosted results, measured budgets and production URL verification
must be reported separately. Nothing in this document claims those runs succeeded.
