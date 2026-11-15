# Build-private adapter certification

The ledger binds eight reviewed, observed schema fixtures to the exact current
internal Go implementation. They cover three country lists, ASN identity, one
monthly city CSV, two free city CSVs extracted unchanged from their original ZIPs,
and a VPN prefix list. Full-payload hash, clock, rights and parser observations
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
