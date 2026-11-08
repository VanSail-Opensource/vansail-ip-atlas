"""Write an explicit incomplete-gate inventory; never synthesize a release pass."""
import json
from pathlib import Path

report = {
    "phase": "local-integration",
    "production_eligible": False,
    "scope": "local compiler, reader, browser and packaging checks on synthetic engineering fixtures",
    "local_evidence_files": [
        "capabilities.json", "codec.json", "codec-bundled.json",
        "node-tests.log", "python-tests.log", "ui-regression.json",
        "reproducibility.json", "static-candidate.json", "performance-local.json",
    ],
    "local_evidence_is_not_hosted_acceptance": True,
    "pending": [
        "hosted-stable-Chrome-bundled-zstd-acceptance",
        "Go-TypeScript-production-VIA3-reader-parity",
        "production-source-schema-certification",
        "qualified-real-source-full-scoring-and-BGP-runtime-invariants",
        "Cloudflare-Pages-preview-route-and-network-regression",
        "full-dataset-hosted-RSS-scratch-and-build-benchmarks",
        "deployed-page-performance-and-accessibility",
        "production-candidate-complete-decoded-VIA3-and-generated-tree-public-scan",
        "24-node-graph-full-theme-viewport-and-accessibility-population",
        "software-runtime-notice-classification-review",
        "exact-artifact-approval-and-production-promotion",
    ],
}
root = Path(__file__).resolve().parents[2]
path = root / "reports" / "pending-gates.json"
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print("Local synthetic integration evidence only; production and hosted gates remain blocked.")
