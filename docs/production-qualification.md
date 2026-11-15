# Production source qualification

`compile-production` consumes authenticated intake; it cannot compile caller
supplied public facts or accept completeness flags. `compile-state` materializing
admitted real records produces private `engineering` artifacts, rejected by the
public packager and deploy verifier. Synthetic fixture compilation is separate:
public synthetic previews contain only synthetic data and have empty real-dataset
credits. Raw `compile-facts` inputs cannot certify a production source.

Current `release-scope-v4` distributes compiled database material under CC BY-SA
4.0, with the exact data-license notice and required included-dataset credits.
This retains v3's single global credit display and v2's optional numeric quality.
Complete negative risk feeds are not required to release null quality with
supported positive reasons. Source-specific rights and all other required
capabilities remain mandatory. The product license alone approves no source.

```powershell
go run ./cmd/atlas intake -workspace . -clock <utc-seconds>
go run ./cmd/atlas compile-production -workspace . -clock <same-utc-seconds> -out build-private/production-atlas -receipt .atlas-private/production-receipt.json
go run ./cmd/atlas verify-production -workspace . -clock <current-utc-seconds> -atlas build-private/production-atlas -receipt .atlas-private/production-receipt.json
```

Intake writes schema-2 private state to `.atlas-private/state-v1.json`. The
historical filename is retained for migration; the version inside the document
selects its schema. Large normalized inputs use immutable content-addressed,
length-framed compressed partitions, each at most 100,000 records and 64 MiB
decoded, with separate encoded and whole-store disk bounds. The per-partition
limit is not a cap on the full source. Legacy inline
state remains readable for engineering use and must pass real intake before
production. A workspace-local key authenticates the exact state bytes and all
partition roots. A production consumer also reopens and hashes every partition;
the seal does not replace rights, schema or freshness checks.

The private qualification receipt binds the source catalog, rights audit,
normalization configuration, current internal Go implementation, fixture ledger,
normalized state, source capabilities, exact release manifest and included
sources. `proof_sha256` denotes the payload digest established by publisher
proof; it is not the SHA-256 of a metadata response. The Go verifier rechecks
current controls, dependencies, actual records, reviewed credits, clocks and
fixture parsing. Caller booleans and matching receipt hashes cannot replace that
source-store verification. The receipt and source-rich capability report must
never enter the public tree or public CI artifacts.

After the compiler verifies its completed immutable output, it also authenticates
the exact canonical receipt, manifest digest, normalized-state digest, policy
binding and deadline with the workspace key. This private content-addressed
attestation is required by `verify-production`; matching editable JSON fields
alone cannot lend a qualified source store to a separately generated database.
Its deadline includes any prior Tier-1 anchor used for stable candidacy. Verification
is read-only and accepts only current or authenticated retained source state.

Capabilities are computed from actual surviving normalized records. Identical
payloads join their evidence-family groups transitively before counting support.
City and coordinate support still require two independent families. BGP requires
an origin mapping and two independent path families; a path-only source need not
also publish a separate mapping. Positive evidence cannot create assessment
coverage. Numeric quality remains optional and insufficient coverage stays null.
The separate Pages acceptance gate requires the exact artifact and measured
hosted evidence; source qualification alone cannot authorize deployment.

Static fixture/rights qualification and actual current intake are distinct.
Derive each report from current bytes rather than preserving a historical count
of active sources. Enabling a reviewed subset does not satisfy missing reason,
usage, routing or other capabilities, and positive-only absence remains unknown.

For release assets, the content clock is the creation time of the exact uploaded
asset whose size and SHA-256 match the download. The enclosing release must be
published and not a draft. A long-lived release tag's creation date is not the
creation date of a newly uploaded asset. The earliest already observed clock for
identical bytes is retained, so a re-upload does not renew known old content.
Mirrors must additionally establish the original publisher's content age; a new
mirror timestamp cannot make an old upstream snapshot current.

MRT capture freshness uses validated frame capture timestamps from the complete,
hashed RIB. An entry's first-heard timestamp is private audit data and is not its
snapshot publication date. The dedicated coordinator requires two reviewed,
independent families, downloads sequentially and enforces one cumulative 1 GiB
compressed budget including failed body reads. Direct generic MRT intake remains
blocked. Qualified Tier-1 history contains only authenticated real capture
epochs; the first eligible snapshot remains pending stability until a genuine
second capture at least 24 hours later. Bounded two-pass UPDATE replay joins exact
peer/session/prefix/ADDPATH identities, handles withdrawals and session resets,
and requires complete contiguous same-collector archives. Ambiguous joins or
replay budget exhaustion fall back to a fresh bounded RIB acquisition. Replay and
no-change reuse retain the earliest base publication clock; they cannot renew it.
Tier-1 stability must use the immediately preceding authenticated observation
without skipping an intervening failed predicate or newer candidate set.

RPKI completeness requires a complete payload-bound authorization snapshot, not
merely a nonempty positive VRP subset. Per-authorization validity remains private;
expired authorizations are excluded and the earliest surviving expiry clamps the
source/release deadline. Private/AS0 authorization ASNs remain available for
validation of public announcement origins without being published as raw facts.
For dated risk observations, the earlier source/item clock controls expiry; a
new wrapper cannot keep an older IOC current.

`state-fingerprints` writes a private NDJSON semantic multiset and a companion
`.meta.json` binding its exact state, byte hash and counts. Container publication
and RIB first-heard clocks are excluded from fact identity; item clocks, family,
weights and actual facts remain. The measurement harness externally compares
these multisets to prove a changed, unchanged, expired or withdrawn input. It
cannot manufacture a one-percent change from a plan flag.

```powershell
go run ./cmd/atlas state-fingerprints -workspace . -clock <utc-seconds> -out build-private/record-fingerprints.ndjson
```

Production facts are withheld until the corresponding static global credit
document verifies. Required publisher links stay visible when full notices are
collapsed. Credits do not waive placement, derivative-license or redistribution
conditions; a source remains ineligible when its obligations cannot be met. The
exact `/data-license.txt` and credit bytes enter the frozen inventory and approval
digest. They identify only included datasets, never a query's provenance.

Full production release also requires the source-free measured acceptance packet
described in [the hosted workflow guide](../tools/hosted/README.md). Unavailable
private bootstrap, a missing metric or a failed threshold blocks promotion. A
synthetic preview or an engineering replay of downloaded files is not production
source coverage. The standard private runner/bootstrap, full real-query and
mutation populations, unchanged lookup/performance thresholds and worst-case
whole-worker memory still require actual measured evidence. This document claims
neither a full production measurement nor a successful production deployment.
