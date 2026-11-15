# Streamed private-state materialization

`BuildStreamedIntelligence` accepts v1 inline or v2 partitioned normalized state
and emits an explicitly synthetic engineering candidate. `BuildIntelligence`
remains the earlier bounded engineering entry and continues to reject production.
`BuildProductionIntelligence` additionally requires a non-nil production gate,
an admission-created `ProductionQualification`, and a source-qualified Tier-1
context. Both qualified objects bind the complete sealed state and build clock.
A caller cannot establish complete VRP coverage with a production boolean.

The producer streams typed records through immutable private spools, recursively
splitting spatial and ASN ranges. Each fusion batch remains at most 200,000
records and 96 MiB of accounted input; IPv4 `/24` neighborhoods are indivisible.
Ancestor geo, usage, origins, coverage and VRPs survive spatial splits. Only
derived quality regions gain partition boundaries: original network and RPKI
announcement prefixes remain intact. Full-source schema/freshness/rights gates
remain separate admission requirements.

Exact positive IP risk is first fused within each complete neighborhood. Its
global per-ASN mass, count and independent-family diversity are accumulated in
canonical address order, then combined with explicit ASN evidence using the
unchanged shared scoring formula. Every later IP and ASN answer uses that same
complete context. There is no per-bucket approximation of ASN risk. Global
context is bounded at 200,000 ASNs, 1,000 families and four million directed
relationships; the process RSS watchdog covers this context too.

Observed paths are sorted externally by canonical typed route structure and
correlated family. Duplicate prefixes/peer rows cannot manufacture independent
visibility. A shared comparator selects twelve routes per origin while retaining
the exact family count for ranking, original prepends/segments and graph
eligibility. Sort buffers remain at most 96 MiB, merge fan-in sixteen and sort-run
inventory 8,192. A single origin can exceed the former 100,000-observation input
batch without a giant in-memory group or a larger limit.

ASN prefixes use a separate external `(ASN, prefix)` union. A typed offline
`ASNPrefixProvider` supplies ordered unique prefixes directly to the unchanged
256-row VIA3 page format. The existing 131,072-prefix inline-slice guard remains;
streamed sources do not construct that slice. The compiler charges every emitted
prefix against its existing 32 MiB compilation estimate and keeps all existing
decoded-object, asset and deployment-file ceilings.

Small ASN lists share those same sorted page objects through the existing
offset/count fields. Shared rows are deduplicated, and interleaved owners receive
ordered spans without mixing their prefixes. This avoids creating one Pages
asset for every ASN; a 20,000-owner fixture uses about eighty page/aggregate/router
objects. A cursor may advance through several spans when owners interleave;
every span retains the existing maximum of 256 prefixes and no prefix is lost.

Normalized state, spool objects, keyed sort runs and compiler scratch share the
10 GiB run ceiling. Before writes, each stage accounts for the other live stages;
the existing physical free-space floor and process RSS watchdog also apply.
Generated spool directories alone are removed on completion or failure. Public
facts have no source IDs, source names, raw peer metadata or provenance fields.

Private partitions now use an outer format-3 `ATNZ` envelope with deterministic
single-thread Zstandard, a 1 MiB maximum window and mandatory checksum. The
original framed typed stream remains inside it; descriptors bind encoded SHA-256,
actual encoded bytes, decoded bytes and record count. The 64 MiB decoded,
100,000-row and 1 MiB-record ceilings remain unchanged. Readers preflight one
exact frame before allocation, reject dictionaries/oversized windows/trailing or
concatenated frames, and validate hashes, checksum, decoded length and count.
Legacy raw `ATNR` partitions and inline v1 state remain readable and migrate
through the same reconciliation logic. Disk reservations charge bytes actually
written by the compressor. This private codec changes no public VIA3 layout.

Focused regressions cover canonical engineering-reader parity across spatial
splits, global ASN contamination bounds, leave-one-out `/24` answers, a single
origin with 200,000 duplicate observations plus 100,005 distinct routes, and
200,005 prefixes for one ASN read through every pagination cursor. These are
engineering correctness/capacity fixtures, not real-source certification or
hosted production acceptance.
