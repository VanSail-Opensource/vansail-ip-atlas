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

`observed-ffraud.csv` is an inactive candidate's minimal observed excerpt from the
2026-11-15 capture of FFraud's original `confirmed-abusive.csv`. It retains the
four publisher comments, column header, and the first complete unchanged row of
each of the eight categories present in that capture, in original order. Its
adjacent [data notice](notices/FFraud-data.txt) preserves the publisher's explicit
MIT data license. These are schema regression inputs, not an admission certificate.

The publisher identifies the category as the worst observed activity from its
own honeypot sensors and community reports. One row yields one exact-IP reason
in one FFraud family. Publisher scores, report counts, and infrastructure types
do not become probabilities, independent votes, usage facts, or extra reasons.
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
