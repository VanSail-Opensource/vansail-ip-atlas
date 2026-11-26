# Build-private adapter certification

The ledger binds reviewed, observed schema fixtures to the exact current
internal Go implementation. They cover three country lists, ASN identity, one
monthly city CSV, two free city CSVs extracted unchanged from their original ZIPs,
a VPN prefix list, timestamped Tor exit observations and ASN usage categories.
Full-payload hash, clock, rights and parser observations
remain in controlled build-private evidence; a fixture is not a production receipt.

An admission fixture must match a reviewed ledger entry for the source, parser/schema version, fixture bytes, test time and current internal Go implementation hash. Changing YAML labels alone cannot certify an arbitrary parser. The actual observed parser run and its private evidence must be reviewed before adding an entry; no tool in this checkpoint invents that evidence or activates a source.

Keep fixtures and receipts out of the deployment tree. The small original CSV
and prefix excerpts preserve captured bytes and line endings; adjacent notices
retain the upstream conditions. `payload_format: decoded-csv` attests only the
observed schema, while actual intake must still verify the complete gzip/ZIP,
publisher checksums or notice, and content clock. Every active source is re-parsed
by `TestReviewedObservedCatalogFixtures` and by the intake certification gate.

Raw subscription bytes and credentials belong only in immediate controlled
build-local quarantine; preserve a sanitized structural fixture and the private
full-payload hash rather than retaining subscription secrets here.

`observed-tor-exit-addresses.txt` is an unchanged descriptor excerpt captured
2026-11-15 from the official TorDNSEL exit list. The Tor Metrics
[data-format documentation](https://metrics.torproject.org/collector.html#type-tordnsel)
describes each `ExitAddress` timestamp as the exit observation time. Its
[data notice](https://metrics.torproject.org/about.html) applies CC0 to the data.
Only literal public addresses and their original observation times are normalized;
relay fingerprints and status metadata remain outside compiled facts.

`observed-ipverse-asn-usage.json` preserves the first 64 complete records of the
2026-11-15 `as.json` capture with a closing array delimiter. The upstream
[README](https://github.com/ipverse/as-metadata/blob/master/README.md) and
[CC0 license](https://github.com/ipverse/as-metadata/blob/master/LICENSE) expressly
cover the data. Categories describe an ASN's primary function, so the compiler
uses them only as fallback context on current observed origin prefixes. ISP/null,
unclassified origins, conflicting MOAS and stale `metadata.lastModified` dates
do not yield a known usage type. `networkRole` does not establish Tier-1 status.

These small excerpts and tests do not establish current source inclusion. Runtime
intake must verify the complete Tor payload or the complete immutable-commit-bound
Ipverse payload and reconcile every retained item clock before qualification.

`observed-ffraud.csv` is a minimal observed schema excerpt from the
2026-11-15 capture of FFraud's original `confirmed-abusive.csv`. It retains the
four publisher comments, column header, and the first complete unchanged row of
each of the eight categories present in that capture, plus the first unchanged
VPN row. The nine-row excerpt covers all four explicit infrastructure types. Its
adjacent [data notice](notices/FFraud-data.txt) preserves the publisher's explicit
MIT data license. These are schema regression inputs, not an admission certificate.

The publisher identifies the category as the worst observed activity from its
own honeypot sensors and community reports. Each row yields its exact-IP threat
reason in one FFraud family. Adapter v2 also retains an explicit proxy, VPN, Tor or
datacenter type as an exact-IP reason in that same family and snapshot clock.
Blank and mobile types remain unknown. Publisher scores and report counts do not
become probabilities, weights or independent votes; no usage fact is inferred.
The observed snapshot has no phishing category rows and supplies no fraud facts.
The versioned schema has no item timestamps; additional date columns are rejected
pending review, rather than silently discarded. Runtime proof requires the full
CSV's independent immutable SHA-256/size match and the same commit's metadata row
count and earlier `generated_utc`. Neither `live_utc` nor a new commit renews it.

`observed-rpki-client-excerpt.json` is an explicitly incomplete schema fixture.
It retains the original metadata field values (including the publisher's
1,034,924 unique-row total) and 21 original authorization rows from the
2026-11-15T12:58:16Z snapshot, including its first expiry. JSON whitespace is
normalized; no publisher count, row value, clock or expiry is changed. The
fixture-only `rpki-client-excerpt` validator shares the strict header and row
decoders but emits no normalized records or completeness/publication proof.
Runtime parsing rejects both this wrapper and these partial rows with the
unchanged full total. Full-payload qualification independently consumed all
1,034,924 rows through EOF; the original capture and digest remain private.
The fixture can certify parser syntax only. Source freshness still uses the
original publisher clock, while RPKI results retain their snapshot observation
and authorization expiry after expiry, as explicitly approved by the user.
Underlying RPKI trust-anchor terms remain in force; the rpki-client software
license does not grant data rights.
`observed-caida-asrel2.txt.bz2` retains all original headers and five unchanged
relationship rows from the complete 2026-11-01 serial-2 capture, then recompresses
that bounded excerpt. Its [notice](notices/CAIDA-serial2-excerpt.txt) records the
upstream terms and the educational decision without claiming a publisher grant.
The earliest explicit topology date is the content clock. The clique annotation
does not establish Tier-1 membership. Tests cover every observed row-provenance
combination, original relationship direction, bounded monthly discovery and full
archive EOF. Its implementation-bound ledger entry certifies the observed parser
run, not current full-payload qualification or production inclusion.

`routeviews-wide-20261115-1200.mrt.bz2` and
`ris-rrc18-20261115-0800.mrt.gz` retain each observed capture's complete original
peer table and sixteen unchanged RIB frames (eight per address family). Their
bounded envelopes are recompressed; frame contents and capture timestamps are
unchanged. Full original payloads were separately consumed through archive EOF.
These excerpts certify schema only, not global route completeness or historical
Tier-1 stability. Adjacent RouteViews and RIPE notices retain original terms and
the educational decision. Exact publisher logo bytes are stored by SHA-256 under
`logos/`; the RouteViews density chunk is preserved without altering pixels.

`observed-tweetfeed-week.csv` retains four complete rows from TweetFeed's
November 22 weekly feed with their original CRLF endings. They exercise a hash,
an IP with an unrelated tag, an untagged IP, and a reported IP with an explicit
phishing tag. Only that last row supplies an observation, dated to its original
UTC report. The publisher dedicates its CSV feeds to CC0 1.0. The publisher
describes the indicators as community reports and asks users to verify them
before taking action. [Feed documentation](https://tweetfeed.live/feeds/)
[Data terms](https://tweetfeed.live/tos/)

All four rows appeared in the canonical static download and the later weekly
artifact with SHA-256
`72575cac4fcc14ba054ba3010d413bcb7a15220f678f3c581a8f2e4e86ba811d`.
The fixture supports schema tests. Production separately requires the publisher
manifest's exact byte count, digest, full CSV row count and original UTC update
time on each intake. When the static CDN has another edition, the verifier may
fetch the exact ready-made CSV named by the current manifest once. Its complete
hash, size and row count must match before any record can enter the atlas.


`observed-dns-root-zone.txt` contains the original 42 selected lines from
the November 22 root zone with SOA serial `2026112200`. They cover the SOA,
apex NS set, its signature lifetime, the ZONEMD serial and the A/AAAA glue
for all thirteen service identities. They exercise all 26 exact-address
outputs. Production verifies the complete publisher text and gzip
distributions and the separately published checksum. The fixture is credited
to the IANA root files and the InterNIC root zone maintainer under the
project's recorded educational-use decision.
[Root files](https://www.iana.org/domains/root/files) ·
[Root service semantics](https://www.icann.org/en/rssac/faq)


`observed-azure-appservice.json` contains four prefixes from the global AppService entry
and the complete Austria East regional entry from Microsoft's November 16 service-tag
file. The four prefixes are the first single-address and wider CIDRs for each
address family, in their original order. All field values are original.
The full global tag has 1,298 CIDRs, including 746 individual IPv4
addresses and one individual IPv6 address.
The fixture exercises single-edition parsing. Live intake independently
checks two complete weekly editions before an address can contribute.
[Microsoft Download Center](https://www.microsoft.com/en-us/download/details.aspx?id=56519)

`observed-nro-delegated-stats.txt` preserves nine original lines from the
November 22, 2026 UTC global edition. It includes the original header, all
three resource-count summaries, an ASN row, an IANA reservation, an assigned
IPv4 range, an assigned IPv6 range and an available IPv6 range. Only the
assigned IPv4 and IPv6 rows produce a registration country, AU and JP
respectively. The 447-byte excerpt certifies the observed schema. Live intake
verifies every row of the original report against the header, all three
summaries and the publisher's SHA-256. [NRO report and scope](https://www.nro.net/about/rirs/statistics/) ·
[Attribution and source terms](notices/nro-delegated-registration.txt)

`observed-google-owned-prefixes.json` retains the original November 25, 2026
Google range-file header and the first two prefixes of each address family.
The 259-byte excerpt preserves the exact field values and record order. The
complete reviewed original contained 148 prefixes. Current intake uses the
original publisher URL and its embedded edition clocks.
[Publisher range definitions](https://docs.cloud.google.com/vpc/docs/access-apis-external-ip#ip-addr-defaults) ·
[Attribution and source terms](notices/google-network-organization.txt)

`observed-ripe-inet6num.txt` retains the original terms header and the
`inet6num`, `netname`, `last-modified` and `source` lines of three
institutional registrations in the November 24, 2026 IPv6 split export. Two
of the labels identify RIPE NCC networks and the third identifies an Amazon
EU registration. The 529-byte excerpt omits contact fields and free text.
Live intake validates the complete primary and UTF-8 exports with their
original server-generated observation clocks.
[RIPE IPv6 object definition](https://docs.db.ripe.net/RPSL-Object-Types/Descriptions-of-Primary-Objects/) ·
[Attribution and terms](notices/ripe-ipv6-network-names.txt)

`observed-mullvad-relay-locations.json` contains the published location records
for Chicago, Zurich and Perth and the ingress addresses and eligibility fields
of one associated WireGuard relay per city. In the signed November 24, 2026
list the Chicago and Zurich relays were active and the Perth relay inactive.
The excerpt preserves the original values. Production intake verifies the
complete content-addressed list, its publisher signature and witness quorum.
[Operator locations](https://mullvad.net/en/help/server-list) ·
[Attribution and source terms](notices/mullvad-relay-geolocation.txt)

`observed-apple-private-relay.csv` contains six complete, unmodified CSV rows
from Apple’s November 19, 2026 publication. Three rows are IPv4 and three are
IPv6. They exercise distinct prefix lengths and include both populated and
empty location columns. Only the first column contributes to the normalized
proxy signal. The sample SHA-256 is
`62a5bf642c6ab7e723548d9a7b000e9b9fecd8b7e0eaaeb232112ae630c8d043`.
The complete original and edition witnesses are recorded in the source audit.
[Publisher CSV](https://mask-api.icloud.com/egress-ip-ranges.csv) ·
[Source audit](../../SOURCES_AUDIT.md) · [Notice](notices/apple-private-relay.txt)
