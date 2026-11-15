# VanSail IP Atlas — Included Source Audit (v3)

## Purpose

This audit documents how **retained** bulk datasets are interpreted, tested and reconciled. There is no per-IP source catalog or source/provenance section in the binary output. Under the user-approved `release-scope-v4`, one global dataset-credit display contains reviewed notices for included datasets and the compiled database uses CC BY-SA 4.0. The compiler retains internal origin family, timestamp and rights status to stop duplicate observations and stale feeds from corrupting reputation.

## Reviewed qualification checkpoint, 2026-11-09

Eight catalog entries now have reviewed rights, observed original-byte fixtures,
implemented parser/publication contracts and code-bound certification. Activation
permits attempted intake; each release still requires a complete downloaded,
current, authenticated receipt. No static admission label proves a current source
or production readiness.

| Admitted source | Reviewed interpretation and rights | Content clock and full-file evidence |
|---|---|---|
| Sapics user-country IPv4/IPv6 and server-country IPv4 | Original-country PDDL; one correlated publisher family, not three votes; country only | Exact uploaded release asset creation time and asset SHA-256, not long-lived release tag time. Complete captures parsed into 420,789 / 568,801 / 403,601 prefixes. |
| Ipverse ASN identity | CC0; ASN name, organization and registration country only; no inferred IP location or usage | File-specific GitHub commit and byte-identical immutable CSV. 125,830 rows, one reserved ASN excluded. |
| DB-IP City Lite direct | CC BY 4.0, visible publisher backlink and modification notice; city centroid precision | Resolve the exact official monthly download; verify complete decoded CSV against publisher SHA1 and MD5. Conservative month-start clock. 7,777,816 rows produced 14,288,199 prefixes. Mirrors remain correlated. |
| ipapi.is free IPv4/IPv6 city subsets | CC BY-SA 4.0, visible publisher credit, modification notice and same-license compiled database, explicitly owner-approved. Free database exemption in publisher terms applies; paid product permissions were not assumed. | Complete ZIP CRC/member/notice checks, exact decoded identities and UTC Extended Timestamp. Actual October 19 member clocks prevail over the November 6 page/HTTP labels. Complete captures contain 4,810,023 / 792,388 data rows. |
| X4B VPN prefixes | MIT list notice plus IPLocate upstream CC BY-SA 4.0 credit; both notices retained. VPN prefix context only, never usage or negative assessment coverage. | File-specific commit and byte-identical immutable list; 11,130 observed prefixes. |

Tiny observed excerpts and required notices are under
`fixtures/source-certification/`, outside every deployment tree. Decoded CSV
fixtures certify the observed schema only: actual intake must still verify the
complete original compressed asset and its publisher clock. Certification binds
the exact internal Go bytes and is invalid after any implementation change until
the observed fixtures are reviewed and run again.

IPAPI accuracy 1/2 allows approximate city centroids, 3 suppresses city and
coordinates, and 4/5 keeps country only. No provider, timezone, postal or continent
column survives normalization. Captured ZIP-local DOS timestamps are insufficient;
only matched UTC extended timestamps establish the conservative content bound.
Previously seen raw or decoded content retains its earliest verified clock.

Other entries remain disabled when rights, freshness, schema, semantics or parser
proof is missing. Feodo's observed March indicators are expired; its newly fetched
container cannot renew them. IPsum and malware-filter aggregate upstream lists
whose combined redistribution obligations remain unresolved. HaGeZi's GPLv3 and
C2IntelFeeds' noncommercial share-alike conditions are not cleared by the owner's
CC BY-SA 4.0 choice. CAIDA's citation/reporting condition and remaining publication
binding, RIPE/RPKI data redistribution rights, complete current RIB qualification,
and other source-specific conditions remain open. Software licenses alone do not
grant rights to their exported datasets.

Complete real-payload parsing is local evidence. The hosted source-intake job
must independently download, verify and reconcile every active source; its public
artifact contains aggregate counts and hashes only. At this checkpoint no current
production receipt or production deployment is claimed. The dated November 8
states below are historical, not current admission controls.

## Canonical source categories

| Source class | Required useful fields | Aggregation strategy |
|---|---|---|
| GeoIP country/city | Country, region, city, coordinates | Resolve by field; never use region inference as street address |
| IP-to-ASN and AS metadata | Prefix, origin ASN, organization/ISP | Longest-prefix and multi-origin preserved |
| Usage classification | IP/prefix, usage-type, evidence | Independent enum separate from abuse |
| VPN/Tor/datacenter | Prefix or exact IP, reason flag | Small explicit evidence contribution, not abusive by default |
| Abuse/botnet/C2 | IP/prefix, threat class, publication epoch | Reliability-weighted and decayed; correlated family max |
| ASN relationship/BGP | ASN pairs, relationship, origin paths | Directional provider/peer/customer; unknown preserved |
| RPKI/registry | Prefix, ASN, route authorization | Per-origin status; distinct from physical location |
| Cloudflare ProxyIP | Literal public IPs from one full list | Mark `proxy=true`; no secondary ProxyIP quality feeds |
| Proxy subscription IPs | Literal public IP server hosts only | Decode then discard transport/URI/port/credentials; mark proxy |

## Retained special feed rules

**Cloudflare ProxyIP:** only the full `Xiaobei09/proxyip/data/valid/all.txt` list is represented. Do not fetch optional quality, region, streaming, China reachability or reputation enrichment from the same project. Treat every emitted public IP as a proxy observation, not as a verified exit IP. Ignore annotations.

**Proxy subscription collector:** all 21 repositories share the sole independence key `public-subscription-aggregators`. Repositories, mirrors and protocol partitions never create separate scoring votes. A direct downloadable file, observed schema, exact publication proof and reviewed redistribution decision are required before activation. Required attribution must be resolved with reviewed global-credit metadata. Do not include HTTP/SOCKS public proxy scraping feeds as another copy of the same intelligence.

**Origin and Tier-1:** CAIDA relationships and current RIB observations serve different purposes. CAIDA inference labels `upstream`, `peer`, `customer` and other relationship classes; RIB paths establish observed adjacency and origin visibility. Source-derived Tier-1 candidates must satisfy provider-free status, globally significant cone/degree and peer-core support. No fixed-ASN allowlist.

**Freshness:** source publication timestamp must be verifiable and within 720 hours; HTTP read time does not count. A stale source is quarantined, its exact and prefix observations removed from the next build, and dependent risk, ASN and `/24` aggregates recomputed. Missing source content must not persist as a residual output record.

**Rights:** public compilation can count as redistribution. Required attribution is now permitted only through reviewed notices in the shared global display; it does not waive redistribution, derivative-use or placement restrictions. Sources whose terms cannot be met remain ineligible. Detailed rights evidence, source IDs and lineage stay private; VIA3 and IP lookup facts remain free of source metadata.

## Proxy subscription decoder fixtures

| Input form | Extract | Reject |
|---|---|---|
| `vless://token@203.0.113.5:443` | Nothing | Documentation address; userinfo/port never output |
| `trojan://token@8.8.8.8:443` | `8.8.8.8` | Credentials and port |
| `vless://token@[2606:4700:4700::1111]:443` | `2606:4700:4700::1111` | URI transport and fragment |
| `vless://token@host.example:443` | Nothing | Domain hosts; no DNS resolution |
| `vmess://<base64-json>` | `add` only when literal global IP | JSON metadata, port, secret |
| Mihomo YAML `proxies[].server` | Literal public IP only | names, ports, credentials, rules |
| sing-box JSON `outbounds[].server` | Literal public IP only | tags, passwords, transports |
| Whole-subscription Base64 | Extract individual embedded literal hosts | nested depth >2, malformed/oversized payloads |

`8.8.8.8` above is a syntax fixture, not an assertion that the address is a proxy. Production validation requires the actual downloaded observation.

## Source verification states

- **Historical catalog, 2026-11-08:** 91 entries, 82 candidate, 7 rights-approved, 2 retired, zero fixture-tested and zero active. At that checkpoint all fixtures were missing; format fragments were reconnaissance only.
- **Rights-approved:** a reviewed allow decision without the remaining schema, fixture, publication or parser proof does not enable publication.
- **Active:** every static admission gate has passed; the November 9 checkpoint above admits eight entries. Runtime proof is still required on every build.
- **Candidate:** URL/format may be documented or unresolved; cannot contribute to production.
- **Stale:** proven publication deadline reached; excluded and all prior influence retracted. Unknown freshness is quarantined.

P0 contract revision 1 normalizes source scopes and field aliases, separates raw fields from public allowlists, removes the dated CAIDA asset and defines two-family sequential MRT acquisition without enabling MRT. Parser IDs, schemas and public field mappings remain explicitly unresolved rather than guessed from these descriptions. No license was newly approved and no source was activated. The derived private capability report, not this audit narrative, determines the current blockers.

No repository description is proof of fresh source data, a working URI, valid credentials or commercial IP classification. All public quality claims must be inferred from the validated downloaded records and bounded rules.
