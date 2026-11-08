# VanSail IP Atlas - Validation Report

## Source catalog cleanup (2026-11-08)

Removed the **4 blocked source entries** from `configs/sources.yaml`, the private discovery inventory, the sample manifest and their format-only documents. No failed entries were present. The current catalog has **91 entries**: **89 captures** (**68 raw**, **21 sanitized**), **2 retired entries**, and **0 blocked or failed entries**. All 89 captured fragments are retained, including all 21 subscription sources. None of the removed entries had dependent sources or captured samples. The prior sample-completion work added 41 of the retained captures; all 48 original fragments remain unchanged.

These are build-private format fragments, not certified parser fixtures, current-source evidence, rights approval, or public data. Admission, evidence families, freshness proofs and fixture status for every retained source are unchanged. No source was enabled or promoted.

### Scope and modified paths

- `configs/sources.yaml`: remove four unavailable source blocks; all other catalog configuration and retained records are unchanged.
- `fixtures/source-samples/discovery.json`: private sample download selections and primary discovery evidence for the 41 retained discovered entries. It is separate from production configuration. Selected partitions demonstrate a format; they do not assert complete source coverage.
- `fixtures/source-samples/samples/`: 41 additional fragments, including all four missing subscription sources. No raw subscription payload was written to disk or logged.
- `fixtures/source-samples/format-only/`: remove the four blocker documents; retain only the two retired records.
- `fixtures/source-samples/manifest.json` and `README.md`: private manifest version 2, sample formats/URLs, hashes, capture-time basis, counts, limits and reproduction instructions. Legacy v1 capture timestamps are explicitly the original index generation time, not a newly observed download time.
- `tools/source_samples/{main,archive,inventory,dns}.go` and regression tests: ZIP local-member prefixes, bounded XZ first-block decoding, discovery selections, integrity-checked retention, failed-recapture preservation, atomic file writes, response rejection, public-address filtering and opt-in public DNS for selected download hosts only.
- `go.mod`, `go.sum`: pin `github.com/ulikunitz/xz v0.5.17` for LZMA2 decoding. Its full XZ reader treats dictionary capacity as a minimum, so the capture tool reads the first block using at most 4 MiB of history rather than allocating the archive's advertised dictionary.
- `IMPLEMENTATION_PLAN.md`, root `README.md` and this report: reconcile source counts, sample coverage and validation status.

Affected input schemas include compressed CSV/TSV, IP/CIDR text, RIR extended statistics, JSON snapshots, MMDB/XDB/MRT binary prefixes, Tor exit-list tar members, and sanitized subscription URI lists. Actual ZIP containers for IPAPI and IPLocate differ from their catalog CSV declarations; the manifest preserves both declarations. Native metadata comments and derivative families remain visible only in private artifacts.

**No retained source policy, VIA3 schema/output, public fields, scoring weights, Tier-1 thresholds, routes or resource budgets changed.** No public bundle or deployment was generated.

### Local verification

- `go test ./...`: passed, including checked-in catalog/sample integrity, sample path coverage, no orphan artifacts, admission/family preservation, subscription checks, ZIP without a central directory, traversal rejection, XZ dictionary bounds, special-IP rejection, malformed VMess redaction, retained capture integrity/time and failed-recapture preservation.
- `go vet ./...`: passed.
- Previous sample-tool fuzz smoke (not rerun for this configuration-only removal): `go test -run '^$' -fuzz FuzzDecodeSample -fuzztime 5s -parallel 2 ./tools/source_samples`: passed, **4,301 executions**, 181 cached baseline inputs, 7 new interesting inputs. This exercises the reconnaissance decoder, not the future production subscription decoder.
- Independent SHA-256/size checks: all 89 fragments match the manifest; all 48 original fragments are byte-identical. Catalog SHA-256 after the four source removals: `307f6b2f7a7b2a46008298df81723ea7c5c2960f0d20abb1bfb89e95b3c043e2`.
- Capture footprint: **516,706 bytes** across 89 fragments; largest fragment **8,192 bytes**. Capture limits: 4 MiB downloaded, 4 MiB decoded, 8 KiB text / 4 KiB binary stored, up to 64 archive entries, and at most 4 MiB XZ history. These are bounds and artifact sizes, not measured process RSS or full-source benchmarks.
- `go test -race ./tools/source_samples`: could not run; this Windows toolchain reports `-race requires cgo` and has `CGO_ENABLED=0`.
- `python -X utf8 tools/validate_blueprint.py`: **failed an existing unrelated check**, `must have exactly one Xiaobei source`. The validator inspects the obsolete `family` field, while the v3 catalog uses `evidence_family`. It reports 91 entries, 0 starter-enabled sources, 21 subscriptions and 17 production catalog subscription URLs. The other four URLs are private sample selections only. Do not treat the older report's structural PASS or seven starter-enabled count as current evidence.

### Current source coverage

The catalog, discovery entries and sample manifest contain no blocked or failed source records. All retained discovery entries select captured artifacts. The two retired sources remain excluded from capture and production admission.

CAIDA's publicly accessible archive indexes supplied genuine PeeringDB and historical bogon samples without submitting forms. The selected September 2025 bogon file is explicitly stale historical reconnaissance and cannot enter a current compilation.

### Pending hosted and production gates

This directory has no Git metadata, remote, hosted workflow or implemented compiler/site. No push, hosted CI, Pages preview/production deployment, Playwright, Go/TypeScript VIA3 parity, scoring/BGP regression, full-source freshness/rights certification, public-output scanner or hosted performance benchmark ran. No hosted gate is claimed as passed.

Full-source RSS, scratch use, p50/p95/p99 runtimes, allocations, browser metrics and Pages deployment budgets remain unmeasured. The local private-fragment checks do not satisfy the material-PR release gates in `AGENTS.md`; production remains blocked on those gates.

Historical workspace backup (not consulted by current catalog or capture commands): `.work-source-samples/` retains the 103 baseline backup files created for this task. Automatic approval review rejected both recursive cleanup and a narrower per-file cleanup with `blocked by policy`; no backup deletion ran. This directory is private and must not enter a public deploy tree.
