# Software notice review

Software notices are independent of IP dataset provenance. Exact installed
license, notice and copyright files are copied without rewriting into
`web/public/licenses`; the canonical notice manifest binds their byte hashes.

`pnpm licenses list --prod --json` is a conservative installed dependency
inventory. It contains build tools, platform binaries and unused component
packages as well as browser dependencies. Missing packaged notices remain in the
private report even when a package is excluded from the browser product.

The private Vite audit in `tools/release_contract/bundle_licenses.ts` records the
actual client and worker module graphs, all transformed module identities and
rendered contributions. Every encountered installed package counts, including a
zero-rendered module. Main assets are captured at `writeBundle`, after Vite has
rewritten preload imports and CSS. Worker ancestry is bound to the exact emitted
worker asset. SSR output cannot replace client evidence. The helper is included
in the deterministic build identity; no source maps or module paths enter public
JavaScript or database objects.

`software_licenses.py --bundle-audit ... --require-runtime-review` validates every
emitted JS/CSS/Wasm byte hash and requires complete code-tree coverage before
accepting an exclusion. A missing notice in either client or worker, an unknown
license label, an unclassified installed module, an extra/mutated/missing asset
or an unbound worker prevents a complete runtime review. This is evidence of
which software is shipped; it supplies no license grants or dataset rights.

Run notice generation before the frontend build so platform-specific installed
notices are already included in the generated static tree, then bind the review
afterwards:

```sh
pnpm --dir web licenses list --prod --json > build-private/software-license-metadata.json
python tools/release_contract/software_licenses.py
pnpm --dir web generate
python tools/release_contract/software_licenses.py --bundle-audit build-private/software-bundle-audit.json --require-runtime-review
```

On the November 8 Windows engineering build, 567 package notices were copied;
25 missing installed-package notices were retained in the private report and
excluded by actual client/worker ancestry. All 60 observed package identities
had copied notices, across 36 verified code assets. Linux hosted builds must
recompute their own evidence rather than reuse these platform counts.
