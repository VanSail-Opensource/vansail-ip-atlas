# VanSail IP Atlas

A Go compiler and Nuxt 4 static IP/ASN atlas. The local synthetic application and authenticated production path are implemented; remaining source qualification, complete production measurements, hosted gates and production deployment are still open. See [implementation status](docs/implementation-status.md) for the exact boundary.

The browser reads indexed, compressed VIA3 objects bundled with the site. It never uses an IP lookup API, resolves subscription hosts, or executes proxy connections. The only external runtime requests are optional OpenStreetMap tiles. IP lookup facts and VIA3 contain no source metadata. A shared footer displays reviewed dataset credits for included data from the same deployment; production facts wait for verified credits, and required publisher links remain visible when full notices are collapsed. Private lineage and source IDs stay private.

Under the owner-approved `release-scope-v5`, compiled database material uses [CC BY-SA 4.0](DATA_LICENSE.md). The exact data-license notice and included-dataset credits are part of each immutable candidate. Source code and software dependencies retain their separate licenses; the product data license does not approve an unreviewed source.

## Local preview

Use the versions in `tools/hosted/toolchains.json`: Go 1.27.4, Node 26.13.1 and pnpm 11.28.12. Python validation dependencies are pinned in `tools/requirements.txt`.

From the repository root:

```powershell
python -m pip install -r tools/requirements.txt
python tools/validate_blueprint.py --report reports/capabilities.json
go run ./cmd/atlas synthetic -graph24 -out build-private/local-atlas
npm exec --yes --package node@26.13.1 --package pnpm@11.28.12 -- pnpm --dir web install --frozen-lockfile --ignore-scripts
npm exec --yes --package node@26.13.1 --package pnpm@11.28.12 -- pnpm --dir web generate
python tools/release_contract/prepare_static.py --atlas build-private/local-atlas --public web/.output/public
python tools/hosted/static-server.py --directory web/.output/public --port 4173
```

Open `http://127.0.0.1:4173/ip`. Synthetic examples are `203.0.113.1`, `203.0.114.1`, `2001:db8::1` and `AS13335`; `AS424240` exercises the artificial 24-node graph. All displayed facts for these fixtures are synthetic. A real address without a fixture remains unknown. Use a fresh atlas output directory when changing the release clock or corpus; packaging rejects unreferenced old objects.

The final prepared deployment directory is `web/.output/public`, including its complete `_atlas/` tree, redirect, CSP/cache headers, data-license notice, global credits and software notices. `prepare_static.py` validates every object, decoded string table, inventory and immutable hash before producing the private candidate report. The commands above package synthetic fixtures; production packaging additionally requires authenticated source qualification and its exact private receipt. Regenerate headers and restart the local static server after rebuilding.

## Verification

```powershell
go test ./...
go vet ./...
python -m unittest discover -s tools -p 'test_*.py' -v
node --test tools/query_contract/query.test.mjs tools/query_contract/via3.test.mjs web/tests/zstd.test.ts web/tests/bgpGraph.test.ts tools/hosted/performance-gates.test.mjs tools/release_contract/bundle_licenses.test.mjs
npm exec --yes --package node@26.13.1 --package pnpm@11.28.12 -- pnpm --dir web typecheck
go test ./internal/subscription -run '^$' -fuzz FuzzLiteralDecoder -fuzztime 5s -parallel 2
go test ./internal/intelligence -run '^$' -fuzz FuzzParseMRT -fuzztime 5s -parallel 2
```

With the prepared static server running, install the locked harness dependencies and run actual stable Chrome:

```powershell
npm exec --yes --package node@26.13.1 --package pnpm@11.28.12 -- pnpm --dir tools/hosted install --frozen-lockfile --ignore-scripts
node tools/hosted/codec-bundled.mjs
node tools/hosted/ui-regression.mjs
node tools/hosted/performance.mjs
```

Selected race tests require a CGO-capable toolchain: `go test -race ./internal/... ./tools/source_samples`. The current Windows environment cannot run them; the [initial hosted integration run](https://github.com/VanSail-Opensource/vansail-ip-atlas/actions/runs/42481869394) passed them on Linux. Its synthetic checks do not establish full-dataset capacity or Pages preview acceptance.

## Implementation map

- `internal/via3`, `cmd/atlas`: versioned container, typed records, indexed readers, compiler work and synthetic release CLI.
- `internal/pipeline`: bounded disk-backed sorting, partitioning and repacking, streamed object emission and nine-kind engineering materialization, including direct ASN identity.
- `internal/admission`: reviewed adapter/fixture checks, exact GitHub asset/immutable-commit publication verification, persistent anti-replay clocks and bounded private intake.
- `internal/intelligence`: scoring, geo/usage fusion, MOAS/RPKI, directed relationships, Tier-1, streaming MRT and typed private reconciliation.
- `internal/subscription`: bounded literal-IP-only subscription syntax decoders.
- `internal/acquire`: pinned public-address HTTP dialing, bounded atomic download and streaming archive inspection.
- `web/app`: hero and all `/ip/*` views, worker lookup/cache, bundled bounded Zstandard decoder, map, graph, themes and keyboard navigation.
- `schemas`, `tools/atlas_contracts`: closed config contracts and derived source-capability report.
- `tools/release_contract`: canonical manifests, expiry, exact approval, full asset packaging, disclosure scanning, CSP hashing and software notices.
- `fixtures/contracts`, `fixtures/bin`, `fixtures/scoring`, `fixtures/bgp`: synthetic engineering fixtures.
- `tools/source_samples`: private historical format reconnaissance. Local captures under ignored `fixtures/source-samples/` are never committed, admission fixtures or production inputs. The private inventory integration check skips explicitly when captures are absent; synthetic parser/security regressions still run.

## Production boundary

The November 15 shortlist contains 14 sources: ten statically admitted entries and four routing candidates. Dated Tor exits and Ipverse ASN categories add observed risk and usage. Every build independently rechecks actual bytes, item clocks, rights and parser certifications; a static active label never proves current production coverage. See [the source audit](SOURCES_AUDIT.md) for remaining qualification blockers.

Production requires qualified real inputs, complete bulk ingestion, measured hosted regression/performance and a verified Pages preview bound to the exact frozen candidate. Under `release-scope-v5`, promotion is automatic from protected main after every mandatory gate passes. Observed risk can report supported positive evidence with explicit incomplete coverage; absent evidence never means safe. Reviewed required logos are local global-credit assets. Source-specific redistribution and credit obligations remain mandatory. The checked-in production policy cannot replace independently verified evidence.

The external planner can also compile the small post-fusion engineering fixture:

```powershell
go run ./cmd/atlas compile-facts -input fixtures/contracts/compiler-facts-v3.ndjson -out build-private/compiled-facts
```

Its NDJSON reader rejects unknown fields, duplicate keys, invalid UTF-8 and oversized records. The output stays synthetic. Raw observations require field-specific materialization first; this command cannot approve or publish a real source.

To revalidate reviewed source controls and retract ineligible records from private state:

```powershell
go run ./cmd/atlas intake
```

This runs all five closed config checks before acquisition, then records private decisions and authenticated normalized state under `.atlas-private/`. Only active, separately certified adapter/proof combinations may acquire data; unsupported adapters, missing rights/fixtures and subscriptions without verified item clocks stay quarantined. Version-2 state streams large sources into compressed partitions, each bounded at 100,000 records and 64 MiB decoded, within the unchanged whole-store and runner budgets. Intake does not produce a public release.

`atlas compile-state -clock <intake-clock> -out build-private/compiled-state`
connects surviving reconciled receipts to bounded engineering materialization.
Admitted real records produce private `engineering` artifacts that public
packaging rejects; they cannot become synthetic previews. `compile-production`
uses authenticated source and Tier-1 qualification, with `verify-production`
checking the exact resulting artifact. See [production qualification](docs/production-qualification.md)
and [production evidence](docs/production-evidence.md) for the commands and
remaining coverage, capacity, preview and approval gates.

The `asn-identity-csv` adapter streams the observed
`asn,handle,description,country-code` schema into direct ASN name, organization
and country facts. It counts/skips reserved ASNs, bounds logical CSV records
before decoding, and preserves unknown field conflicts. It does not infer IP
location, usage, relationships or Tier-1 class. The full observed 125,830-row
publisher CSV is supported by partitioned intake without raising the per-partition
limits. Its reviewed source admission is separate from full production capability
and runner-capacity acceptance.
