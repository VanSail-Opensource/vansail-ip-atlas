# Regression and performance harness

This directory is build-private. Never copy it, its lockfile, or its reports into
the Pages public tree. The scripts do not activate sources or deploy anything.

Pinned tools are in `toolchains.json` and the package/Go lockfiles. `web/package.json`
and `web/pnpm-lock.yaml` freeze frontend dependencies. Chrome is deliberately the current stable branded
channel; record its exact version on every run rather than freezing an obsolete
browser. The pinned Node baseline is 26.13.0; record the actual Node version with
each report. A local Chrome or Node run does not establish hosted acceptance.

From the repository root:

```powershell
go run ./tools/hosted/golden
python -m unittest tools.release_contract.test_contracts -v
node tools/hosted/codec-probe.mjs
node --test web/tests/zstd.test.ts
node tools/hosted/codec-bundled.mjs
python tools/hosted/evidence-status.py
python tools/release_contract/prepare_static.py --atlas build-private/synthetic-atlas --public web/.output/public
node tools/hosted/performance.mjs
```

Install the harness with the exact package manager and frozen lockfile:

```powershell
cd tools/hosted
npm exec --yes --package pnpm@12.18.0 -- pnpm install --frozen-lockfile --ignore-scripts
npm exec --yes --package pnpm@12.18.0 -- pnpm exec playwright install chrome
```

`codec-probe.mjs` preserves the native diagnostic, which failed on local Chrome
156.0.8078.80 and exits nonzero. The user's 2026-11-08 C06 amendment authorized one
pinned bounded bundled Zstandard decoder, retaining VIA3 codec1. `codec-bundled.mjs`
bundles the pinned fzstd dependency and product wrapper, then runs real golden hashes,
truncation, checksums, pre-allocation window rejection and emitted-output guards in
actual Chrome. Its local twelve-case run passed; report `reports/codec-bundled.json`.
There is no alternate codec or remote decoder. The shared Go/TypeScript corpus
tests all fourteen VIA3 kinds, canonical answers, corruption, expiry and query
cancellation. Full-process memory, real-source parity and hosted execution remain
separate gates.

`performance.mjs` requires the prepared local static server on port 4173 (or an
immutable HTTPS deployment-hash Pages `ATLAS_PREVIEW_URL`). Generate its candidate
using `go run ./cmd/atlas synthetic -graph24 -out build-private/synthetic-atlas`,
then prepare the static tree as above. It records twenty cold mobile hero samples, five cold
synthetic lookups, actual gzip-level-9 initial JS bytes and sixty graph event-to-paint
samples with p50/p95/p99. The artificial AS424240 graph has twelve retained routes,
exactly 24 visible nodes and 23 actual synthetic adjacencies. Active pan/zoom/focus
measurements each run ten seconds; every complete one-second population must reach
50 FPS. CPU/network emulation and the host/browser versions are recorded. Pages
runs write `performance-preview.json`; local runs retain `performance-local.json`.
Field INP, complete interaction CLS, browser peak memory, full dataset capacity and
the full theme/viewport protocol remain unmeasured. Overall/hosted acceptance stays
false. Budgets are unchanged and a measured graph failure exits nonzero.

`.github/workflows/p0-contracts.yml` runs on main pushes, pull requests and manual
dispatch. It includes Go/race/fuzz/static checks, source-free contract reports,
shared reader tests, bundled Chrome decoding and the complete synthetic static
tree's local HTTP regression. A successful run preserves the exact public tree as
`atlas-synthetic-public` and its source-free candidate/UI/performance reports as
`synthetic-integration-evidence`, both with seven-day retention. Source-rich
capabilities, samples, intake state and lineage are never uploaded by these jobs.

Deploy the unchanged `atlas-synthetic-public` artifact to a Pages preview through
the connected Cloudflare tool or reviewed Direct Upload procedure. Do not rebuild
it. Then manually dispatch `.github/workflows/pages-preview.yml` with that
successful main integration run ID and its immutable deployment URL, for example
`https://a01b23cd.project.pages.dev`. Branch aliases and production domains are
rejected. The workflow verifies the originating trusted run, downloads both
artifacts, checks the full candidate digest and unexpired manifests, fetches every
served file, compares exact bytes/hashes, checks effective CSP/cache headers and
the HTTP root 302, then runs current-stable Chrome UI/privacy regression. Identity
and expiry are checked again afterward. Controls `_headers`/`_redirects` are
validated through their deployed effects because Pages does not serve them as
ordinary assets. The workflow has no deployment credential or production job.

`python -m unittest tools.hosted.test_candidate -v` covers unchanged artifacts,
expiry, production rejection, URL restrictions, exact served bytes and security
headers. `python tools/hosted/candidate.py --public web/.output/public` rechecks a
prepared candidate locally; add `--preview-url` for deployed identity verification.

These engineering workflows do not satisfy full real-source coverage, hosted
capacity/accessibility/performance, legal approval or protected production
promotion. `evidence-status.py` preserves those pending gates. Adding a workflow
does not claim that it has run; consult the exact revision's actual Actions result.
