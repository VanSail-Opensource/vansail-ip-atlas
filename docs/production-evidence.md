# Production evidence and private bootstrap

The production path is implemented separately from synthetic fixture previews
and private known-real engineering artifacts. Its existence is not a source
approval, successful capacity measurement or authorization to publish. Under
`release-scope-v4` (approved 2026-11-09), compiled database material uses CC BY-SA
4.0 and exact included-dataset credits; numeric quality remains optional.
Complete negative risk feeds are not a release prerequisite. Missing assessment
coverage yields null quality, while other required source capabilities and
measured release gates remain mandatory.

Source-by-source qualification is advancing. Do not infer current counts from
the historical zero-active checkpoint, and do not infer runtime eligibility from
an active catalog label. Current authenticated intake, certification bytes and
actual hosted reports decide eligibility. No source can be enabled by supplying
a success flag to these tools.

The 2026-11-09 checkpoint has eight locally parsed observed source fixtures;
current static activation still depends on the final code-bound ledger. Local
Go acquisition is constrained by nonpublic DNS answers, which remain rejected.
The dedicated hosted source-intake job is separate evidence: successful downloads,
parsing and sealed reconciliation are not inferred from local fixture tests.
The infrastructure audit on that date found no registered production self-hosted
runner, and no full production capacity/browser run is claimed here.

`atlas compile-production -workspace . -clock <UTC-seconds> -out <private-atlas>
-receipt <private-receipt>` consumes authenticated normalized intake state.
`atlas verify-production` independently reopens that state, current policy, rights,
adapter certification and every record chunk. Raw `compile-facts` cannot certify a
production source. The closed canonical receipt v1 binds:

- `schema_version:1`, `release_scope:"release-scope-v4"`, `mode:"production"`;
- `evaluated_at`, `valid_until`, `release_id`, `release_manifest_sha256`;
- `source_catalog_sha256`, `rights_audit_sha256`,
  `normalization_config_sha256`, `implementation_sha256`,
  `certification_sha256`, `normalized_state_sha256`,
  `source_capabilities_sha256`;
- ordered unique `included_sources`, each with `source_id`,
  `payload_sha256`, `proof_sha256`, `published_at`, `expires_at`,
  `parser`, `schema`, `parser_version`, `evidence_family`,
  `rights_sha256` and nullable `attribution_sha256`.

`proof_sha256` is the publisher-proven exact payload hash, equal to
`payload_sha256`; it is not the hash of an arbitrary metadata file. Rights and
credit hashes cover exact canonical catalog metadata. No receipt is public.
`normalized_state_sha256` excludes random authentication keys/HMAC bytes; identical
verified inputs and clock remain deterministic. This does not permit reconstruction
from newer mutable assets. A retained release needs its original authenticated
eligible state, not the new current state's inclusion set.

The canonical acceptance packet has exactly `format_version:1`,
`scope:"production-acceptance-v1"`, `repository`, `head_sha`, `release_id`,
`candidate_bundle_sha256`, `qualification_receipt_sha256`, `preview_url`,
`preview_deployment_id`, `assembled_at`, `integration_run_id`, and `artifacts`.
The repository is `VanSail-Opensource/vansail-ip-atlas`. The artifacts array contains
one `candidate` and one `preview` entry with `kind`, `run_id`, `artifact_id`, and
`artifact_sha256`. IDs are positive integers; hashes are lowercase SHA-256. The
preview URL must use its immutable UUID hash host. A packet references evidence;
writing these fields cannot make a failed report pass. `promotion.py` downloads
and verifies the actual trusted artifacts and all raw gates before accepting it.

The candidate evidence archive contains exactly `static-candidate.json` and
`production-build.json`. The preview archive contains exactly
`preview-identity.json`, `production-browser.json` and `pages-deployment.json`.
Each report binds the same
frozen candidate/release. Source-rich reports, receipts, plans, state seals,
fingerprints, payloads and private child logs stay outside these archives.

The frozen public inventory also contains `/data-license.txt`, the shared credit
index and every referenced immutable credit document. Packaging validates the
exact compiled-data notice and derives credits from the verified inclusion set.
Unused candidate datasets cannot receive credits. Changing a notice or credit
changes the candidate bundle digest and requires a new preview and approval.
Software dependency notices are a separate obligation.

`promotion.py --assemble --head <exact-revision> --integration-run-id <id>
--candidate-run-id <id> --preview-run-id <id> --public <frozen-public>
--qualification-receipt <private-receipt> --evidence <new-private-packet>` fetches
trusted evidence, derives every gate and rechecks the live preview before writing
a new canonical packet. It refuses to overwrite an existing review packet. Its
assembly clock must follow completed CI. Approval remains a separate final step.

The private benchmark plan has `format_version:1`, `mode:"production"`, and 15
`cases`: three each for `cold_full`, `warm_changed`, `warm_unchanged`,
`clock_advance`, and `withdrawal`. Each case has exactly `scenario`, `sample`
(1–3), `workspace` (relative to the plan directory), `before_clock`, `clock`, and
`overlay`. Every case uses a distinct exact-head checkout with reviewed pinned
input/bootstrap state. The six baseline cold/unchanged cases use the candidate's
same evaluation clock. Only source catalog/audit/certification inputs may be
overlaid; entries have exact private `from`, workspace-relative `to`, and
`sha256`. No shell command can be provided by the plan.

`state-fingerprints -workspace <workspace> -clock <UTC> -out <private-NDJSON>`
revalidates authenticated state and emits private `{source_id,semantic_sha256}`
rows plus `<out>.meta.json`. The build harness external-sorts bounded 32-MiB runs,
preserves multiplicity and compares actual before/after records. The changed case
must replace exactly one percent with unchanged population; unchanged must alter
zero records. Expiry/withdrawal must actually retract the affected sources, even
when the correct result is blocked compilation because required coverage is lost.
Aggregate counts/digests alone enter public evidence. A plan claiming “one percent”
cannot supply the missing measurement.

The browser corpus has exactly `format_version:1`, `mode:"production"`,
`interaction_query`, `graph_query` and 10000 `queries` with `q` and `stratum`.
The strata cover IPv4/IPv6 exact and LPM, MOAS, sparse/dense ASN, inherited and
unknown cases. The interaction IPv4 must genuinely expose the evidenced map;
the real graph query must project 24 observed nodes with selectable routes.
`production-browser.mjs` runs 30 independent contexts for each of four widths in
both themes, complete trusted search/map/navigation/Class-C/graph actions,
Event Timing lab INP estimates, complete-session CLS and axe-core checks. It also
measures 100 cold IP queries and 1000 actual cached worker lookups after warmup
in each of three contexts. No threshold is raised for missing or slow populations.

Chrome process-tree RSS is sampled at 100 ms and explicitly records its accounting
limitations. It is a diagnostic, not proof of the separate 384-MiB worst-case
whole-worker envelope. That gate remains unmeasured until an isolated cgroup peak
and the accepted worst-case profile are actually exercised and bound. Unsupported
Event Timing, incomplete accessibility checks, missing populations and worker
memory proof remain blocking. No production browser run is claimed by this file.

The private workflow requires a verified Linux runner with the actual standard
2-vCPU/8-GiB/14-GiB profile, pinned original input/bootstrap state and a real-query
corpus. Public artifacts cannot bootstrap private source state. The existence
of a workflow or a locally parsed full feed does not establish that this
infrastructure or the mandatory production measurements have run. Full build
populations, semantic mutations, allocation accounting, versioned performance
comparison, real-query lookup distributions and the worker-memory envelope need
their own evidence. Earlier synthetic/local latency results do not pass those
gates; the unchanged Go lookup target is 2 microseconds.

All contributing source/item/content deadlines must remain valid through the
measured preview and promotion. In particular, a short VRP authorization lifetime
cannot be extended to accommodate a long browser protocol. Missing private
inputs, insufficient validity, unmeasured metrics and failed thresholds remain
blocking. `compile-state` artifacts carrying admitted real data are private
`engineering` releases and are rejected by public candidate packaging; they are
not synthetic previews and cannot bypass required legal assets or qualification.
