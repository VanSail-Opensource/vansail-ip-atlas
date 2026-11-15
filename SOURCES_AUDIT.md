# VanSail IP Atlas - Production Source Audit

## Current shortlist - 2026-11-15

The v6 release catalog contains ten reviewed active intake candidates. The four
unqualified routing entries were removed after the user explicitly approved
verified-data release with unavailable routing facts shown as unknown. Active permits attempted intake; it is
not a current authenticated source receipt or production approval. Public data
uses release-scope-v6, observed risk and CC BY-SA 4.0 compiled-data distribution.
There is no per-IP source catalog or public provenance section.

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

## Excluded routing sources; qualification remains unresolved

| Candidate | Remaining conditions |
|---|---|
| ripe-mrt-rrc01 | Current commercial-use/CC BY-SA compatibility review; required logo/link/acknowledgement legal assets; exact current full RIB, capture clocks and observed fixture. |
| routeviews-rib | Explicit current data redistribution grant review; independent complete current RIB and capture/schema certificate within shared MRT budget. |
| caida-asrel2 | Public acceptable-use citation/date/publication-reporting review and CC BY-SA compatibility. No external notification sent. Exact serial2 body and publication binding; filename date alone is not proof. |
| rpki-client-vrps | Actual RPKI data/relying-party redistribution rights, not software license alone. Complete current JSON/expiry/completeness certificate. Prior payload had approximately 101 minutes validity: measure headroom without omitting valid short-lived authorizations. |

These feeds are excluded from the production catalog. Their facts remain unknown;
no origin, relationship, RPKI not-found result or Tier-1 membership is inferred.
Reintroduction requires the rights, full-payload and fixture conditions above.
Parser implementation and source labels cannot substitute for that qualification.

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
