# Bounded offline compiler

`Build(ctx, Options, Producer)` accepts versioned, fully fused `via3.PublicRecord`
facts. It external-sorts private length-framed runs, merges at most 16 readers at
once, deduplicates identical identities, rejects conflicting identities, and
compiles bounded partitions. It checks actual compressed object sizes against
the configured asset target before committing a partition. Record, input-buffer,
decoded-object and actual-byte limits trigger recursive IP/ASN repacking;
indivisible oversized scopes fail instead of losing facts.

The prefix planner copies original ancestor prefixes into inherited sections.
It never replaces an observed network/RPKI prefix with a partition boundary.
Identical inherited objects shared across partitions have manifest scope `all`;
the indexed router still selects the correct partition destinations. IPv4 `/24`
profiles and a single ASN cannot be split internally. The ASN compiler already
pages prefix lists at 256 prefixes per object.

Default limits remain inside the checked-in resource contract: 96 MiB sort
buffer, 16 MiB serialized partition buffer, 8 MiB single private record, 32,768
records per partition, 8,192 active sort-run entries, strictly less than 24 MiB
per asset, fewer than 18,500 objects, 10 GiB compiler scratch, 6.5 GiB compiler
process RSS and a 1 GiB physical free-space floor. Router metadata is capped
before accumulation by the 32 MiB public decoded-object limit. These implementation
ceilings can reject a source workload; they never permit truncation or establish
full-source capacity by themselves.

`Limits.ObjectBytes` may tighten the physical asset target. The planner measures
each compiled object's compressed bytes, recursively repacks before writing an
oversized candidate, and checks the final router too. A router that cannot fit
the target fails; this package does not introduce an unversioned router format.

Every run and staging file is private beneath the exact newly created
`Workspace/.atlas-private/pipeline-*` directory. Scratch bytes are charged before
writes and released only after successful deletion. The Windows/Linux resource
sampler polls at 100 ms; process RSS is its OS lifetime high-water value. It
includes this Go process, not a complete process group. The supplied producer
must honor context cancellation and invoke `emit` synchronously. Its own input
allocation, unrelated preexisting caches/output trees and child processes require
the separate hosted process-group/physical-disk harness.

The output must be a new directory under `Workspace/build-private`. Objects are
written and discarded one partition at a time; only bounded object/router metadata
is retained globally. The manifest and pointer are built last. A production
callback must succeed before input and again before atomic publication. No
production callback or source approval is supplied by this package.

`Options.InputGate` independently revalidates caller-owned inputs before input
and immediately before atomic publication in either mode. Failure retracts the
candidate without replacing any prior release. It never supplies the production
capability approval.

`BuildMappings(ctx, options, state, policy)` is the mapping-only entry point. It
refuses production and requires the release validity deadline to be no later
than the earliest surviving source receipt. Its lower-level
`MappingProducer(state, policy, clock)` callback connects a revalidated private
`intelligence.BuildState` to the complete Geo/Usage/Origins subset. It requires
the exact evaluation clock and nonexpired source receipts. Every geographic or
usage boundary is fused from applicable local/ancestor observations; descendant
records at `prefix.Addr()` cannot influence the parent. More-specific conflicts
and anycast boundaries emit unknown geo/usage rows and coordinate tombstones;
missing child fields keep eligible factual parent fallback. MOAS/network records
keep their actual observed prefix and all unique origins.

This materializer rejects unsupported risk, coverage, VRP, path and relationship
records before emitting any rows. It is not a complete production materializer,
admission engine, or Tier-1 derivation pipeline. It has a 96 MiB accounted working
input ceiling, at most 200,000 records/1,000 receipts, and at most 8,192 applicable
geo or usage observations at one boundary. The full production source set still
needs streamed table-specific risk/BGP/ASN materialization and real-source
certification. A mapping-only release must not satisfy the full production gate.

`BuildIntelligence(ctx, options, state, policy, MaterializationInputs)` now
materializes all eight currently defined normalized record kinds for engineering
releases. It reuses geographic/usage/MOAS fusion and adds four-layer quality,
sparse exact-observation `/24` profiles, ASN contextual risk and prefix pages,
per-announcement/per-origin RPKI, ranked typed observed paths and directed
relationships. Quality uses a bounded binary radix to produce disjoint regions
at every prefix/exact/coverage/origin and affected `/24` boundary. Each point
sample is therefore constant throughout its region; an exact observation at a
parent's first address cannot contaminate the parent. Source-specific names and
families never enter public rows. Nonlinear/looped/private-ASN paths retain their
original typed segments but cannot create graph edges.

This path requires the same reconciliation clock and nonexpired receipts, keeps
the 96-MiB/200,000-record input ceiling, and caps its change-boundary radix at one
million nodes. It still buffers a bounded complete state and is not full-source
streamed production ingestion. Missing/partial VRPs are unavailable; the explicit
`VRPComplete` engineering assertion plus retained nonempty VRP data is necessary
to compute valid/invalid/not-found. No ASN identity is inferred from a path,
address or relationship. This state schema has no certified Tier-1 history or ASN
identity union, so positive Tier-1 classification/ASN labels remain unavailable
and the entry point rejects production unconditionally.

The concrete `atlas compile-state` command reads only the fixed private state
created by `atlas intake`. It holds the intake writer lock and binds the exact
configuration, review ledger, internal code and state bytes before and at
publication. Policy/certification changes require new intake; changed clocks
require new reconciliation so decay cannot be hidden by a cache hit. The release
deadline defaults to the earliest surviving receipt. An empty intake produces no
candidate. For a future admitted engineering run use one shared UTC clock:

```powershell
$atlasClock = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
go run ./cmd/atlas intake -clock $atlasClock
go run ./cmd/atlas compile-state -clock $atlasClock -out build-private/compiled-state
```

The current catalog has no surviving admitted sources, so these commands
deliberately stop with no candidate after intake. The new CLI tests construct
explicit synthetic private state and verify a complete state-to-public-reader
round trip plus source withdrawal, policy change, expiry and production refusal.

Run `go test ./internal/pipeline` and `go vet ./internal/pipeline` for the focused
regressions. They cover multiple merge generations, ordering/dedupe/conflicts,
actual compressed-byte repacking, broad-prefix inheritance and tombstones,
IPv4/IPv6/ASN indexed answers, mapping withdrawal/conflicts/anycast/MOAS, exact
clock checks, unsupported record rejection, production withdrawal at publication,
parent cancellation, RSS/free-space/scratch aborts and cleanup.

`GOMAXPROCS=2 go test ./internal/pipeline -run '^$' -bench
BenchmarkDiskBackedCompile -benchtime 12x -benchmem` measures a deliberately small
256-record synthetic corpus with forced sort and partition boundaries. It prints
raw samples, nearest-rank p50/p95/p99, allocation count, input bytes, owned scratch
and this process's RSS high-water. It does not establish full-source throughput,
hosted acceptance, physical whole-runner disk use or the required process-group
RSS budget.
