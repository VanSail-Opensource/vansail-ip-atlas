# Build-private adapter certification

The certification ledger is deliberately empty. Implemented parsers and historical format samples do not establish observed source certification.

An admission fixture must match a reviewed ledger entry for the source, parser/schema version, fixture bytes, test time and current internal Go implementation hash. Changing YAML labels alone cannot certify an arbitrary parser. The actual observed parser run and its private evidence must be reviewed before adding an entry; no tool in this checkpoint invents that evidence or activates a source.

Keep fixtures and receipts out of the deployment tree. Raw subscription bytes and credentials belong only in immediate controlled build-local quarantine; preserve a sanitized structural fixture and the private full-payload hash rather than retaining subscription secrets here.
