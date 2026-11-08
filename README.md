# VanSail IP Atlas

A Go compiler and Nuxt 4 static IP/ASN atlas. The local synthetic application is runnable; real-source qualification, complete production ingestion, hosted gates and production deployment remain blocked. See [implementation status](docs/implementation-status.md) for the exact boundary.

The browser reads indexed, compressed VIA3 objects bundled with the site. It never uses an IP lookup API, resolves subscription hosts, or executes proxy connections. The only external runtime requests are optional OpenStreetMap tiles. All source metadata stays build-private.

## Local preview

Use the versions in `tools/hosted/toolchains.json`: Go 1.27.3, Node 26.13.0 and pnpm 12.18.0. Python validation dependencies are pinned in `tools/requirements.txt`.

From the repository root:

```powershell
python -m pip install -r tools/requirements.txt
python tools/validate_blueprint.py --report reports/capabilities.json
go run ./cmd/atlas synthetic -graph24 -out build-private/local-atlas
npm exec --yes --package node@26.13.0 --package pnpm@12.18.0 -- pnpm --dir web install --frozen-lockfile --ignore-scripts
npm exec --yes --package node@26.13.0 --package pnpm@12.18.0 -- pnpm --dir web generate
python tools/release_contract/prepare_static.py --atlas build-private/local-atlas --public web/.output/public
python tools/hosted/static-server.py --directory web/.output/public --port 4173
```

Open `http://127.0.0.1:4173/ip`. Synthetic examples are `203.0.113.1`, `203.0.114.1`, `2001:db8::1` and `AS13335`; `AS424240` exercises the artificial 24-node graph. All displayed facts for these fixtures are synthetic. A real address without a fixture remains unknown. Use a fresh atlas output directory when changing the release clock or corpus; packaging rejects unreferenced old objects.

The final prepared deployment directory is `web/.output/public`, including its complete `_atlas/` tree, redirect, CSP/cache headers and software notices. `prepare_static.py` validates every object, decoded string table, inventory and immutable hash before producing the private candidate report. It refuses production mode. Regenerate headers and restart the local static server after rebuilding.

## Verification

```powershell
go test ./...
go vet ./...
python -m unittest discover -s tools -p 'test_*.py' -v
node --test tools/query_contract/query.test.mjs tools/query_contract/via3.test.mjs web/tests/zstd.test.ts web/tests/bgpGraph.test.ts tools/hosted/performance-gates.test.mjs tools/release_contract/bundle_licenses.test.mjs
npm exec --yes --package node@26.13.0 --package pnpm@12.18.0 -- pnpm --dir web typecheck
go test ./internal/subscription -run '^$' -fuzz FuzzLiteralDecoder -fuzztime 5s -parallel 2
go test ./internal/intelligence -run '^$' -fuzz FuzzParseMRT -fuzztime 5s -parallel 2
```

With the prepared static server running, install the locked harness dependencies and run actual stable Chrome:

```powershell
npm exec --yes --package node@26.13.0 --package pnpm@12.18.0 -- pnpm --dir tools/hosted install --frozen-lockfile --ignore-scripts
node tools/hosted/codec-bundled.mjs
node tools/hosted/ui-regression.mjs
node tools/hosted/performance.mjs
```

Selected race tests require a CGO-capable toolchain: `go test -race ./internal/... ./tools/source_samples`. The current Windows environment cannot run them; the [initial hosted integration run](https://github.com/VanSail-Opensource/vansail-ip-atlas/actions/runs/42481869394) passed them on Linux. Its synthetic checks do not establish full-dataset capacity or Pages preview acceptance.

## Implementation map

- `internal/via3`, `cmd/atlas`: versioned container, typed records, indexed readers, compiler work and synthetic release CLI.
- `internal/pipeline`: bounded disk-backed sorting, partitioning and repacking, streamed object emission and a Geo/Usage/Origins materializer.
- `internal/admission`: reviewed adapter/fixture checks, exact GitHub asset publication verification, persistent anti-replay clocks and bounded private intake.
- `internal/intelligence`: scoring, geo/usage fusion, MOAS/RPKI, directed relationships, Tier-1, streaming MRT and typed private reconciliation.
- `internal/subscription`: bounded literal-IP-only subscription syntax decoders.
- `internal/acquire`: pinned public-address HTTP dialing, bounded atomic download and streaming archive inspection.
- `web/app`: hero and all `/ip/*` views, worker lookup/cache, bundled bounded Zstandard decoder, map, graph, themes and keyboard navigation.
- `schemas`, `tools/atlas_contracts`: closed config contracts and derived source-capability report.
- `tools/release_contract`: canonical manifests, expiry, exact approval, full asset packaging, disclosure scanning, CSP hashing and software notices.
- `fixtures/contracts`, `fixtures/bin`, `fixtures/scoring`, `fixtures/bgp`: synthetic engineering fixtures.
- `tools/source_samples`: private historical format reconnaissance. Local captures under ignored `fixtures/source-samples/` are never committed, admission fixtures or production inputs. The private inventory integration check skips explicitly when captures are absent; synthetic parser/security regressions still run.

## Production boundary

The catalog still contains 91 entries: 82 candidates, seven rights-approved entries and two retired entries. Zero sources are active; all real parser fixtures remain missing, no source declares complete risk coverage, and no real capability currently qualifies. All 21 subscription repositories share one scoring family. No rights decision, attribution exception or source activation was invented during implementation.

Production requires all required capabilities, real-source schema/freshness/rights certification, complete bulk ingestion/repacking, hosted regression and performance, a verified Pages preview and approval bound to the exact candidate. Under the user-approved `release-scope-v2`, numeric quality is optional: unavailable assessment coverage leaves it unrated and does not block release; positive reasons still appear. Its scoring eligibility rules remain unchanged. `configs/release-approval.yaml` remains default-deny. No GitHub repository, push or deployment is required to use the local synthetic preview.

The external planner can also compile the small post-fusion engineering fixture:

```powershell
go run ./cmd/atlas compile-facts -input fixtures/contracts/compiler-facts-v3.ndjson -out build-private/compiled-facts
```

Its NDJSON reader rejects unknown fields, duplicate keys, invalid UTF-8 and oversized records. The output stays synthetic. Raw observations require field-specific materialization first; this command cannot approve or publish a real source.

To revalidate reviewed source controls and retract ineligible records from private state:

```powershell
go run ./cmd/atlas intake
```

This runs all five closed config checks before acquisition, then records private decisions and normalized state under `.atlas-private/`. The current catalog admits zero sources and makes no download requests. Only the implemented, separately certified adapter/proof combinations can acquire data; unsupported adapters, missing rights/fixtures and subscriptions without verified item clocks stay quarantined. Intake currently enforces a 64 MiB normalized-state ceiling and does not produce a public release.

`atlas compile-state -clock <intake-clock> -out build-private/compiled-state`
connects surviving reconciled receipts to bounded engineering materialization.
It rechecks config/certification/state identity, clock and expiry at publication.
With the current empty intake it rejects the build rather than inventing facts.
See [the pipeline contract](internal/pipeline/README.md) for supported inputs and
the remaining bulk/Tier-1/ASN-identity gates. Production mode remains refused.
