# VanSail IP Atlas — Included Source Audit (v3)

## Purpose

This audit documents how **retained** bulk datasets are interpreted, tested and reconciled. There is no per-IP source catalog or source/provenance section in the binary output. Under the user-approved `release-scope-v3`, one global dataset-credit display contains reviewed notices for included datasets. The compiler retains internal origin family, timestamp and rights status to stop duplicate observations and stale feeds from corrupting reputation.

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

- **Current catalog, 2026-11-08:** 91 entries, 82 candidate, 7 rights-approved, 2 retired, zero fixture-tested and zero active. All fixtures remain missing; format fragments are reconnaissance only.
- **Rights-approved:** seven entries have a reviewed allow decision but still have unresolved `attribution_required: null`, missing observed fixtures and no certified parser. This peer milestone does not enable publication.
- **Active:** every static admission gate has passed; no current catalog entry qualifies. Runtime proof is still required on every build.
- **Candidate:** URL/format may be documented or unresolved; cannot contribute to production.
- **Stale:** proven publication deadline reached; excluded and all prior influence retracted. Unknown freshness is quarantined.

P0 contract revision 1 normalizes source scopes and field aliases, separates raw fields from public allowlists, removes the dated CAIDA asset and defines two-family sequential MRT acquisition without enabling MRT. Parser IDs, schemas and public field mappings remain explicitly unresolved rather than guessed from these descriptions. No license was newly approved and no source was activated. The derived private capability report, not this audit narrative, determines the current blockers.

No repository description is proof of fresh source data, a working URI, valid credentials or commercial IP classification. All public quality claims must be inferred from the validated downloaded records and bounded rules.
