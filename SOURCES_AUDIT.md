# VanSail IP Atlas - Production Source Audit

## Current shortlist - 2026-11-15

The v6 catalog contains fifteen reviewed entries enabled for attempted intake,
including the five replacements below. Active
permits attempted intake; it is not a current authenticated receipt or production
approval. Public data uses release-scope-v6 and observed risk. Original compilation
contributions retain CC BY-SA 4.0; upstream material retains its recorded terms,
including explicit user-authorized educational-use decisions where compatible
redistribution permission is unresolved. There is no per-IP source catalog or
public provenance section.

| Entries | Reviewed meaning and rights | Publication/parser evidence |
|---|---|---|
| Sapics user-country IPv4/IPv6 and server-country IPv4 (3) | PDDL original country data; one correlated family, country only | Exact uploaded asset time and SHA-256. November 9 complete captures:420789/568801/403601 prefixes. |
| DB-IP City Lite direct (1) | CC BY 4.0; global backlink and modification notice; city centroid precision | Complete monthly CSV, publisher hashes, conservative month-start clock. November 9:7777816 rows/14288199 prefixes. |
| ipapi.is free city IPv4/IPv6 (2) | Free WHOIS-derived CC BY-SA 4.0 subset, global credit and same-license adaptation | Complete ZIP CRC/member/notice and UTC Extended Timestamp. Earlier October 19 clocks prevail over newer wrapper labels. November 9:4810023/792388 rows. |
| Ipverse ASN identity (1) | CC0; name, organization and registration country only | Path-specific commit plus identical immutable CSV; earlier complete capture: 125,830 rows. |
| X4B VPN IPv4 (1) | MIT list notice and upstream IPLocate CC BY-SA 4.0 credit | File-specific immutable commit; earlier capture: 11,130 VPN prefixes. Prefix context only, no direct usage or negative coverage. |
| Tor current exits (1) | Official Tor Metrics CC0 data; positive exits only | November 15 complete 438,145-byte body: 2,794 current literal public observations; original ExitAddress clocks retained. Earliest surviving 2026-11-13T03:17:00Z. |
| Ipverse ASN usage JSON (1) | CC0 primary ASN function, only observed-origin fallback | November 15 complete 70,172,159-byte JSON matched immutable 942f7eb297bb6c9db589a430cddaab7f01c58e0c, published 02:28:16Z. Parser emitted 63,912 unambiguous public-ASN categories; 1,591 within 720h. ISP/null and stale categories stay unknown. |

Small observed excerpts and notices are in fixtures/source-certification/.
Full raw captures and clock/hash observations remain build-private. Final
certifications bind observed fixture tests to the exact internal Go code.
Hosted intake must independently verify and reconcile complete source bytes.
No current full production qualification or hosted deployment is claimed here.

Tor meaning and CC0 dedication were checked in the publisher's
[format documentation](https://metrics.torproject.org/collector.html#type-tordnsel)
and [data notice](https://metrics.torproject.org/about.html). Ipverse's
[license/category documentation](https://github.com/ipverse/as-metadata/blob/master/README.md)
makes categories contextual defaults; networkRole never establishes Tier-1.

## Reviewed replacements — enabled for attempted intake

| Entry | Observed complete payload and exact integration boundary |
|---|---|
| routeviews-wide-rib | Complete dual-stack 2026-11-15 12:00 RIB: 4,010,726 route observations, 294,930,007 decoded bytes. Explicit scheduled archive rotation retains the embedded frame clocks; unsupported origins keep empty LPM boundaries. RouteViews is one original path family. CC BY 4.0 data grant, publisher boilerplate and exact logo are retained; additional terms and logo restrictions use the recorded educational decision. |
| ripe-mrt-rrc18 | Complete dual-stack 2026-11-15 08:00 RIB: 1,351,173 route observations, 126,487,987 decoded bytes. Same finite full-snapshot, EOF and capture-clock requirements, a distinct original RIS family, and exact reviewed scheduled rotation. Required RIPE NCC boilerplate, link and publisher PNG are retained; revocation and general-logo conditions remain accurately recorded. |
| caida-asrel2 | Complete serial-2 body: 680,178 inferred directed relationships. Exact monthly index selection and the earliest dated topology input bind freshness; the observed dates span November 1–5. Filename/HTTP time never renews age. Data derives from RouteViews/RIS and looking-glass inputs, not another independent path vote. Input-clique annotations are not Tier-1 membership. Public AUA/citation/reporting conditions remain recorded under the educational decision; no publisher notification was sent. |
| rpki-client-vrps | Complete original 1,034,924-row publisher snapshot with every VRP and original expiry retained. Validation uses the payload-bound publisher build time. Schema-5 results expose observation and deadline, keeping expired results as historical snapshot observations. Source freshness still ends at original publication plus 720h. The 21-row fixture retains original metadata totals and emits no runtime proof. Underlying trust-anchor terms are recorded separately from the software license. |
| ffraud-ip | Complete 1,651,503-row original CSV bound to its immutable file and same-commit metadata; two nonpublic literals are excluded. The earlier generated_utc is 2026-11-03T21:30:44Z, not a new download clock. Eight observed categories yield six distinct threat reasons in this capture, with no phishing/fraud rows. Adapter v2 additionally retains 189,501 explicit proxy/VPN/Tor/datacenter observations, yielding 1,841,002 normalized records from 1,651,501 public IPs. Blank/mobile types stay unknown. All reasons share one original family and clock; scores/counts never become calibrated probability, weights or independent votes, and no usage type is inferred. The full original MIT data notice is included in the global credit. |

These five entries have observed parser fixtures, implementation-bound
certifications and reviewed global notices. Their active status permits attempted
intake. Current production eligibility still requires complete
fresh input bytes, authenticated receipts, semantic validation and every measured
gate. Source status does not fabricate global routing coverage, negative RPKI
coverage, historical Tier-1 stability, or missing detection observations.

MRT downloads share the unchanged 1 GiB compressed budget and validate complete
archives within 3 GiB decoded per source. WIDE/RRC18 rotation permits a 30-minute
publication lag and exactly one previous archive only after HTTP 404. Corrupt,
truncated, stale or mismatched successful responses cannot fall back. Actual
archive URLs and clocks remain sealed privately and are preserved by replay.

## November 22 phishing observations

TweetFeed's November 22 weekly CSV contained 2,406 community reports. Of the
254 IP rows, 40 explicitly tagged phishing and identified 37 distinct public
addresses. Their UTC report times ranged from November 16 at 02:27:39 to
November 22 at 13:00:57. The publisher's manifest bound that revision to
307,037 bytes and SHA-256
`72575cac4fcc14ba054ba3010d413bcb7a15220f678f3c581a8f2e4e86ba811d`.
The captured four-row excerpt contains one qualifying report.
[Feed documentation](https://tweetfeed.live/feeds/)

Release intake fetches the static weekly CSV from the publisher and checks its
byte count, row count, digest and publication time against the publisher's
manifest. When the static server lagged behind the manifest, the verifier
retrieved the manifest's designated publisher CSV once and matched its 2,408
rows and 307,265 bytes at 14:30:40 UTC. It contained the same 40 qualifying
reports. The verifier accepts only the complete edition authenticated by the
manifest.
Only an explicit phishing tag on a public IP contributes the existing fraud
reason. The original report time governs its age. Reporter handles, post links,
domains and URLs are discarded. The two community feeds share one scoring
family because their report origins can overlap. The source weight of 35
reflects the publisher's description of the data as community reports.
TweetFeed releases these feeds under CC0 and makes attribution optional.
[API and manifest documentation](https://tweetfeed.live/api/) · [Publisher terms](https://tweetfeed.live/tos/)

## Anycast addresses of DNS root services — November 22

ICANN's Root Server System Advisory Committee identifies thirteen root service
identities, each using anycast routing with one IPv4 and one IPv6 address.
Intake reads the complete IANA root zone through the published InterNIC files
and joins only its apex NS identities to their exact A and AAAA records.
The separate gzip decoded to the same 2,245,813 bytes and SHA-256
`e004a209dbddd68837f2d0b4b84336b4e42395d385e8cbb46239006eda5bdaa2`.
The maintainer's checksum also matched. The observed SOA serial `2026112200`
dates the snapshot to November 22 at 00:00 UTC. The minimum relevant DNS TTL
bounds these 26 positives to November 28 at 00:00 UTC.
[Root files](https://www.iana.org/domains/root/files) ·
[RSSAC FAQ](https://www.icann.org/en/rssac/faq) ·
[SOA serial convention](https://newgtlds.icann.org/sites/default/files/root-scaling-27jun12-en.pdf)

Other IPs receive no anycast or location assertion from this source. The
weekly or daily anycast censuses considered during research report measured
prefixes. Some IPv4 ranges mix unicast and anycast, and published prefix
measurements do not identify every responding host. This release uses exact
service addresses for the address-level lookup.
[University of Twente census methodology](https://github.com/ut-dacs/anycast-census#partial-anycast)

The repository records educational use with global attribution. IANA's CC0
statement covers protocol registries. The domain root zone is published
separately and retains its upstream terms.
[IANA licensing statement](https://www.iana.org/help/licensing-terms) ·
[ICANN terms](https://www.icann.org/en/data-protection/terms-of-service)

## Removed production entries; retained independent tests

All other old catalog entries were removed, including 21 unqualified subscription
repositories. Their literal-IP decoder and hostile syntax/security fixtures
remain. Feodo observations were stale; SSLBL IP feeds deprecated; mixed X4B
datacenter output cannot establish unconditional usage. Unresolved aggregate,
noncommercial and otherwise incompatible feeds were not promoted.

Tor and X4B provide separate positive-observation families. Every supported
category and view remains available, but absent categories are unknown; no
per-category feed is required and unlisted never means safe. Usage joins retain
most-specific observed origins, direct IP/prefix priority and MOAS unknowns.

## Historical reconnaissance states - 2026-11-08

- **Historical catalog, 2026-11-08:** 91 entries, 82 candidate, 7 rights-approved, 2 retired, zero fixture-tested and zero active. At that checkpoint all fixtures were missing; format fragments were reconnaissance only.
- **Rights-approved:** a reviewed allow decision without the remaining schema, fixture, publication or parser proof does not enable publication.
- **Active:** every static admission gate has passed; the November 9 checkpoint above admits eight entries. Runtime proof is still required on every build.
- **Candidate:** URL/format may be documented or unresolved; cannot contribute to production.
- **Stale:** proven publication deadline reached; excluded and all prior influence retracted. Unknown freshness is quarantined.

P0 contract revision 1 normalizes source scopes and field aliases, separates raw fields from public allowlists, removes the dated CAIDA asset and defines two-family sequential MRT acquisition without enabling MRT. Parser IDs, schemas and public field mappings remain explicitly unresolved rather than guessed from these descriptions. No license was newly approved and no source was activated. The derived private capability report, not this audit narrative, determines the current blockers.

No repository description is proof of fresh source data, a working URI, valid credentials or commercial IP classification. All public quality claims must be inferred from the validated downloaded records and bounded rules.
