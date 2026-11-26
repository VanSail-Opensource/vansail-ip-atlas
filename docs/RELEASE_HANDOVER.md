# Production release handover — November 26, 2026

**The public website is offline.** At 08:34 UTC the canonical IP page returned HTTP 404. PR #1 merged on November 15. Protected `main` is at `c5480fd7e8c95102f6769ca4c561e1a3f46846c8` with 22 sources. The 23-source release and checkpoint repair are on open PR #7, branch `codex/production-sources-complete-v11`, head `225b1dc79cff6af4d6f2436b79f958e86b9ba8e3`. All four required PR checks passed. [Canonical site](https://vansail-ip-atlas.pages.dev/ip/) · [PR #1](https://github.com/VanSail-Opensource/vansail-ip-atlas/pull/1) · [PR #7](https://github.com/VanSail-Opensource/vansail-ip-atlas/pull/7)

## Evidence at handover

| Revision and check | Verified outcome |
| --- | --- |
| [PR #7 integration](https://github.com/VanSail-Opensource/vansail-ip-atlas/actions/runs/45595989395) | All 23 sources current. Compiled 38,685,529 observations in 15m 21.884s. The website contained 11,594 files and 136,572,153 bytes. Full native lookup p95 was 10.710 µs across 100,000 calls. |
| [Protected 22-source candidate](https://github.com/VanSail-Opensource/vansail-ip-atlas/actions/runs/45589466787) | Verified all 11,512 public files. Release ID `19bf2fbf1a013d097958dd45f643832c05711ba68951cc7c5497bfd0fd78a9eb`. Its eligibility deadline is November 28 at 00:00 UTC. Local Chrome exercised all five views, all 12 risk categories, dated RPKI results, subscriber ISP boundaries and the keyboard-accessible 256-cell grid. |
| [Protected benchmark matrix](https://github.com/VanSail-Opensource/vansail-ip-atlas/actions/runs/45593977336) | All 15 jobs stopped while restoring the encrypted candidate, before measurement. The writer generated extended tar headers for 101-byte state-history and 107-byte receipt paths. The reader rejected them. PR #7 writes USTAR and restores both generations in real encrypted round-trip tests. |
| [November 26 scheduled intake](https://github.com/VanSail-Opensource/vansail-ip-atlas/actions/runs/45782462517) | The latest scheduled run on the 22-source main failed at encrypted-state restoration. Candidate and benchmark dispatch were skipped. This run did not exercise the PR #7 repair. |
| [23-source withdrawal and expiry](https://github.com/VanSail-Opensource/vansail-ip-atlas/actions/runs/45583574200) | Separate hosted engineering measurements removed 285,226 withdrawn records in 7m 36.800s and 1,645 expired records in 6m 19.318s. |
| [Changed and unchanged rebuilds](https://github.com/VanSail-Opensource/vansail-ip-atlas/actions/runs/45596172207) | The unchanged case passed in 56.525s. The changed case recorded a successful native exit in 3m 2.209s, then the enclosing engineering check exited 1. Verification of the changed-record transition is still open. |

## Where to resume

1. Inspect artifact `source-free-intake-status` in the changed-rebuild run above. Compare `warm_changed-measure-preflight.json` with `warm_changed-measure-budget.json` and the post-measurement checks on `codex/production-23-warm-check` at `4b3ccd0`. Reproduce the one-percent change and verify the before/after row counts. The elapsed time alone cannot establish a passing result.
2. Land the tested checkpoint repair through PR #7 when the changed-rebuild discrepancy is understood. Follow the new protected main commit through integration, intake, candidate, all 15 benchmark cases and their join. Record the new candidate's release ID and inventory digest. [Release workflows](https://github.com/VanSail-Opensource/vansail-ip-atlas/actions)
3. Follow that candidate through the immutable Pages preview, worker-memory check and nine Chrome shards. If a preview needs a retry, dispatch the full preview against its successful benchmark join so the jobs share one attempt's artifacts. After promotion, check the canonical redirect, release pointer, inventory, credits and all five views in Chrome. [Release contract](release.md) · [Performance limits](performance.md)

## Data decisions and unfinished research

Publish verified observations, show explicit unknowns where evidence is missing, and retain expired RPKI snapshot results with their observation and expiry dates. The owner approved a 25 µs launch limit for full native lookup p95. The other build and website limits still apply. Source-specific terms, the owner's educational-use decisions and attribution are recorded in the source audit. [Source coverage and terms](../SOURCES_AUDIT.md)

PR #7 includes Apple Private Relay, subscriber ISP observations from four operators, and signed Mullvad relay locations. The Seattle Internet Exchange publishes actual interface addresses and masks that may support exact IPv4 directed-broadcast observations. This was source research only. The 23-source release includes no SIX adapter. Address assignment mode remains unknown where the operator supplies no direct evidence. [SIX participant CSV](https://www.seattleix.net/autogen/participants.csv) · [SIX exchange inventory](https://www.seattleix.net/autogen/participants.json)
