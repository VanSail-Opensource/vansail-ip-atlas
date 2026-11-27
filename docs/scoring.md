# Scoring and fusion contract, revision 3 - observed risk

`configs/scoring.yaml` is authoritative. This amendment changes numeric-score
semantics and separates positive support from assessment coverage. It preserves
every signal coefficient, half-life, contextual support formula and 0.15 geo
margin. It is not a calibration or real-source certification. Reference vectors are in
`fixtures/scoring/observed-risk-v1.json`; `python -m unittest discover -s
tools/contract_vectors -p "test_*.py"` checks the synthetic vectors.

## Current approved amendment - observed-risk v1, release-scope-v5

Model `via-observed-risk-v1` replaces higher-is-better quality with a 0-100
**observed risk** index, where higher means more supported adverse evidence.
VIA3 public schema 6 retains the observed-risk meaning introduced in schema 4.
Older readers and data cannot be mixed with it. This is not a probability, a safety rating or a claim
that absent evidence establishes safety. The historical scope amendments below
record earlier decisions; this amendment supersedes their numeric-score rules.
All signal coefficients, age decay, independence, scope specificity, layer weights
and contextual caps are unchanged. Source rights and freshness remain mandatory.

## Release-scope amendment `release-scope-v2` — 2026-11-08

The user made numeric quality optional for production release and removed the
prerequisite to obtain two complete risk-assessment families before releasing.
This does not revise model `via-risk-v3-contract-1`, its coefficients, half-lives,
coverage qualification or confidence thresholds. The existing two-family and
four-assessed-layer requirements below still govern every non-null numeric score.
When they are unmet, retain `quality=null`, unrated confidence and supported
positive reasons; do not infer clean from absence or assign a substitute number.
The quality view and all scoring/unrated invariants remain mandatory even when
numeric quality is unavailable throughout a production snapshot.

## Dataset-credit amendment `release-scope-v3` — 2026-11-08

The v3 amendment retains v2's optional numeric quality and permits
reviewed legally required dataset credits in a separate global frontend display.
Credits describe included real datasets only. They are neither risk evidence nor
a per-IP provenance claim and never enter VIA3 records or lookup answers. An
attribution-required source may pass rights admission when its reviewed global
credits satisfy the actual terms; every other source/coverage test still applies.
Source counts, brand names and credit entries cannot create independent evidence
votes, confidence or numeric quality. Model revision 1 and all formulas remain
unchanged.

## Compiled-data license amendment `release-scope-v4` — 2026-11-09

Current release scope adds the owner-approved CC BY-SA 4.0 license for compiled
database material, with the exact data-license notice and included-dataset credits
bound into the immutable candidate. It retains the v2 and v3 rules above. The
product data license grants no rights to an unreviewed source and changes no
scoring coefficient, coverage threshold, evidence family or public fact field.
Source code and software dependencies retain their separate licensing terms.

## Observation, scope and independence

Reject nonfinite or out-of-range evidence inputs. Reliability is
`clamp(source_weight / 100, 0, 1)`; severity and specificity use the configured
signal and scope values. Normalize `cloudflare_proxyip` into `proxy`, `c2` into
the public reason `command_control`, and `scanner` into public reason `scanning`
before signal/family deduplication. `cloudflare_proxyip` is not a second beta term.

For canonical signal `d`, family `f`, and applicable scope:

`e(d,f) = max_i(reliability_i * severity_i * specificity_i * 2^(-age_i / half_life_d))`

The age clock is the earlier verified item publication time and source payload
publication time when an item clock exists, otherwise the verified source time.
This prevents a newly wrapped old item becoming new. Source freshness and item
expiry are checked before decay. A clock more than 24 hours ahead quarantines the
source; a future clock within tolerance has age zero. Local/fetch/cache/304 clocks
are never inputs. See `docs/source-policy.md` for retention and stricter expiry.

The dedupe key is `(layer, applicable target, canonical signal, evidence_family)`.
Mirrors, protocol lists, publisher partitions and all 21 subscription repositories
do not create extra votes. One family may support several different signals, but
each signal has only its maximum family contribution. Exact host observations
belong only to the exact layer; a containing prefix or origin never changes their
scope. Explicit source CIDRs use LPM for applicability, then the maximum family
contribution across all matching explicit indicators. ASN records must explicitly
name that ASN. Provider/customer neighbors do not inherit those records.

`R_layer = 1 - exp(-sum_d(beta_d * sum_f e(d,f)))`

All sums use canonical signal order from the config, ascending UTF-8 family bytes
within a signal, and ascending numeric addresses for address aggregates. Maximums
and dedupe precede summation. Calculations use binary64 with no intermediate
rounding. Final public quantization is specified by the binary contract; weighted
contributions use millionths, half-up once at serialization. Golden arithmetic
vectors use absolute tolerance `1e-12` before quantization. Go/TS parity must also
test exact serialized integers and boundary vectors; tolerance never excuses
different canonical bytes.

## Observed risk, independent support and assessment coverage

For every IP, preserve the four existing weighted contributions, their presence
and their unrounded binary64 values:

`Robs = clamp(sum of present contributions, 0, 1)`

`S = floor(100*Robs + 0.5)`, including zero when observations are missing.

Missing applicable contributions are returned as numeric zero without changing
their unassessed status. The storage format keeps their presence mask. Summing supported
contributions is a lower-information observed-evidence model, not an estimate
of total real-world risk. Do not renormalize missing layers, invert the former
integer quality, or compute the score from rounded serialized contributions.
Authoritative complete negative observations may produce present zero layers,
but without a scored positive contribution the public number is zero and
confidence is unrated. A tiny supported positive number may round to zero. The
UI displays `<1 / 100` with its positive reasons, never "safe".

IPv4 and IPv6 both support observed-risk numbers. IPv6 has no `/24` layer: its
neighbor contribution remains null/not applicable and the remaining weights
stay 0.55, 0.18 and 0.15. The absent 0.12 weight is not redistributed. The IPv6
`/48` summary is separate and does not change the address score.

### Subnet summary denominators

The IPv4 `/24` summary sums its published per-address scores and divides by 256.
Unobserved addresses contribute zero to that mean, but are never assessment or
observation counts. The grid still distinguishes observed from unobserved cells.

The IPv6 `/48` summary groups current deduplicated exact host observations by
their `/64` prefix. Each nonempty `/64` contributes the highest rounded weighted
exact-IP risk contribution, at most 55 points. Missing `/64` blocks contribute
zero. Sum all bucket contributions and divide by 65,536, with no expansion to
individual addresses and no grid. Expose the score sum, denominator and counts of
observed and positive `/64` blocks. Neither these counts nor a numeric zero assert
complete assessment. Prefix and ASN signals are not multiplied across the blocks.

Confidence describes independent positive support, separately from assessment
coverage. For each strictly positive contributing layer, one or two current
independent positive families give low, three give medium, and four or more give
high. The overall band is the weakest such layer. The ASN layer takes support
from the origin giving the maximum weighted contribution; tied maxima use the
weaker support. The neighbor layer uses families retained after self-exclusion.
A repeated family across layers cannot create extra votes. Zero-contribution
layers do not affect positive-support confidence; without a positive weighted
sum confidence is unrated. This is neither calibration nor probability.

Coverage retains the former conservative assessment test. A layer is assessed
only when a current admitted complete family covers its entire required scope:
exact address, complete explicit-prefix assessment at that address, every MOAS
origin for ASN, or all 255 other IPv4 `/24` cells for neighbors. Coverage is
complete only for IPv4 with a current origin mapping and at least two common
complete families intersecting all four scopes and all origins. Otherwise it is
incomplete. Public `observedRisk.coverage` exposes this status and per-layer
assessed/unassessed/not_applicable states, never family identifiers or counts.
Coverage does not gate, inflate or erase a supported observed-risk score.

The exact-malware example with weight 100 and age zero gives
`R_exact=0.8646647167633873`, weighted exact `0.475565594219863`, and observed
risk 48 whether other assessment coverage is absent or complete. The reasons
and unsupported-layer states remain visible. Half-up rounding uses the computed
binary64 value with no epsilon or intermediate rounding; the golden corpus
includes half boundaries, tiny positive values and absent evidence.

## ASN context and MOAS

ASN identity fusion is independent of contextual risk. Each of name,
organization and ASN country takes at most one current vote per family: choose
the highest reliability and abstain on conflicting values at that reliability.
Across remaining families, a field's highest reliability wins only when the
value is unique at that weight. Equal-weight conflicts remain unknown. Missing,
stale and zero-weight fields abstain. This direct identity never supplies usage,
IP geography, relationships or Tier-1 membership and changes no risk coefficient,
coverage requirement or score calculation.

For one origin, first deduplicate its current exact addresses and calculate each
address's exact positive risk as above. Do not count CIDR expansion or inferred
addresses. Let `P` be the unique addresses whose exact risk is greater than zero:

- `u_asn = sum_{i in P} R_exact_i`, a bounded positive risk mass, not source count.
- `distinct_positive_ips = |P|`.
- `independent_families` is the union of current positive families supporting
  these exact addresses or an explicit adverse ASN record, once per family.
- `C_asn_diversity = min(1, independent_families/3)`.
- `C_asn = C_asn_diversity * min(1, distinct_positive_ips/64)`.

`R_asn = max(R_explicit_asn, (1-exp(-u_asn/256))*C_asn_diversity)`

`R_explicit_asn` uses only explicit ASN-scope indicators and specificity 0.30.
Both diversity factors in the original equations are intentional: the inner
factor supports inferred risk mass, and the outer confidence supports contextual
influence. An explicit ASN indicator without current exact-address support has
`C_asn=0`, so its reason can be shown but its IP observed-risk contextual contribution
is zero. This consequence is explicit; substituting a different confidence
formula would require another reviewed model revision.

Current MOAS mapping may associate one observed address with each actual origin;
it does not choose one origin or divide the host risk. Compute the entire formula
independently for every origin. An unassessed origin prevents complete assessment coverage, not observed risk. Take `max_origin(0.15*C_asn*R_asn)` for the single
weighted ASN contribution. Never union origins' counts before computing it.
All origins remain visible as network facts. The maximum is monotone under added
independent positive evidence and cannot exceed 0.15.

The public ASN context band uses the unweighted `R_asn` serialized in millionths:
absent is `unknown`, present values below 333334 are `low`, values 333334 through
666666 are `medium`, and values at least 666667 are `high`. These initial equal
range bins are uncalibrated context descriptions, not ASN quality scores or
claims that every address in the ASN has that risk. They do not change scoring.

A single address with risk 0.8 from one family gives `C_asn=1/192`,
`R_asn=0.001040040756597286`, and weighted contribution
`0.0000008125318410916296`. This is contextual support, not evidence that other
customers are malicious. Malicious exact reasons are never copied to an ASN,
subnet or another address. Residential/mobile fixtures keep unrelated host risks
absent and provider/customer influence zero.

## Leave-one-out `/24` context and profile

Use only unique, current exact-address positive observations in the queried
IPv4 `/24`, excluding the queried address before counting either families or
addresses. Calculate each remaining host's exact positive risk once:

`D24 = sum_{i != q}(min(1,R_exact_i))/255`

`R24 = 1-exp(-16*D24)`

`C24 = min(1,unique_positive_neighbor_ips/16)*min(1,independent_families/3)`

The family count is the union supporting retained positive neighbors; aliases
and duplicates do not add addresses or families. A denominator of 255 is a
density model, never a claim of assessment coverage. One neighbor at risk 0.8
gives `R24=0.04895707278807204`, `C24=1/48`. Removing the query's own observation
also removes a family supported only by that observation.

The 256-cell profile retains unknown cells and exact positive reasons. Only
actually observed cells receive per-cell observed-risk scores. `scoredCount`
counts their non-null scores and `meanObservedRisk` is the half-up arithmetic
mean of those integer scores, null when the count is zero. Unknown cells never
enter the denominator or become zero. `assessedCount` separately counts observed
cells with complete assessment coverage. Counts/distributions describe observed
cells only; the mean is labelled with its scored-observed denominator, not as a
score of all 256 addresses. A tie for dominant ASN is unknown, and MOAS addresses contribute to
each actual origin's observation count without inventing one primary origin.

## Geographic fusion

Physical country and registration country are separate vote domains. For each
field, each current mapping family first takes its applicable LPM records. It
has at most one vote: use the highest source reliability, and abstain on equally
weighted conflicting field values. Same-family mirrors never break a tie.
Missing values and zero-weight votes abstain. Normalize country to uppercase
alpha-2; normalize region/city labels to NFC, collapse whitespace and preserve
case for display. Compared geographic identities use parent country and region
IDs, not display label alone. Invalid hierarchy records abstain.

Country takes a unique weighted-plurality winner with at least one supporting
family. A weight tie is unknown. Region voting uses only families whose physical
country matches the selected physical country. City voting additionally requires
the selected region. For each level the denominator is the sum of **all**
nonmissing eligible family vote weights at that level, including losing places.
The margin is `(winner_weight - runner_up_weight)/denominator`; runner-up is zero
if only one place is present. Region and city require at least two **agreeing**
independent families for the winning place and margin `>=0.15`. Two participating
families that disagree do not satisfy support. No parent winner means no child.

Coordinates require the accepted city. Among families agreeing on its identity,
choose a record with valid coordinates by reliability descending, precision
class descending, then canonical public coordinate/precision bytes ascending.
This tie-break never uses source names and copies one complete coordinate pair
and its uncertainty; never average or mix latitude and longitude. Quantization
and precision flags follow the VIA3 contract and never imply finer precision.
If no agreeing record has coordinates they stay unknown. Explicit anycast clears
physical city/coordinates and suppresses the map; it does not manufacture a
registration fact or clear independently supported country/region facts.

## Usage, assignment and invariants

Usage needs direct classification with one normalized vote per family. If two
current direct classifications disagree, usage is `unknown`; reputation, country
and network ownership do not break the conflict. Assignment uses canonical public
`assignment_mode`: `native`, `broadcast_or_routed`, `unknown`. Source aliases are
adapter inputs only. Anycast and IPv4 directed broadcast have independent
presence bits and never imply assignment or malicious activity.

Independent additional positive evidence cannot reduce observed risk. Duplicate-family replay, source order and same-family mirrors
cannot affect output. Assessment coverage and positive-support confidence are tested separately.
No exact malicious indicator propagates its reason to another host. ASN and
neighbor influences remain capped at 0.15 and 0.12, including residential/mobile
bias sentinels. These hypotheses still require held-out calibration and hosted
regression; passing the synthetic vectors is not evidence that real-source
coverage or production quality is available.
