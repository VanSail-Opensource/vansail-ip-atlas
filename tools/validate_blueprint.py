#!/usr/bin/env python3
"""Strict P0 validation and build-private capability report; no source fetching."""
import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import sys
from atlas_contracts.config import ContractError, ROOT, load_configs
from atlas_contracts.policy import capability_report, utc


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, help="private JSON output, outside web/")
    parser.add_argument("--now", help="UTC clock for repeatable contract tests")
    parser.add_argument("--require-production", action="store_true")
    args = parser.parse_args()
    try:
        configs = load_configs()
        now = utc(args.now) if args.now else datetime.now(timezone.utc)
        report = capability_report(configs["sources"], now, ROOT)
        report["config_sha256"] = {name: sha256((ROOT / "configs" / f"{name}.yaml").read_bytes()).hexdigest() for name in configs}
        if args.report:
            destination = args.report.resolve()
            if destination.is_relative_to((ROOT / "web").resolve()):
                raise ContractError("capability reports must stay outside web/")
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"PASS: strict contracts; {report['source_count']} sources; {report['active_count']} active; {report['current_count']} current")
        blocked = [row["capability"] for row in report["capabilities"] if row["required"] and row["status"] != "qualified"]
        print(f"Production BLOCKED: {len(blocked)}/{report['required_capability_count']} required capabilities: {', '.join(blocked)}")
        quality = next(row for row in report["capabilities"] if row["capability"] == "numeric_quality")
        print(f"Optional numeric quality: {quality['status']}; insufficient coverage remains unrated")
        return 2 if args.require_production and not report["production_eligible"] else 0
    except (ContractError, ValueError, OSError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
