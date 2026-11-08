"""Copy exact installed software notices; keep package paths/review gaps private."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
NOTICE = re.compile(r"^(?:license|licence|copying|notice|copyright)(?:[._-].*)?$", re.IGNORECASE)
DIRECT = {
    "fzstd": "fzstd.txt", "leaflet": "leaflet.txt", "nuxt": "nuxt.txt", "@nuxt/ui": "nuxt-ui.txt",
    "vue": "vue.txt", "vue-router": "vue-router.txt", "motion-v": "motion-v.txt", "tailwindcss": "tailwindcss.txt",
}


def generate(metadata: Path, output: Path, report_path: Path) -> dict:
    records = json.loads(metadata.read_text(encoding="utf-8-sig"))
    module_root = (ROOT / "web/node_modules").resolve()
    output.mkdir(parents=True, exist_ok=True)
    chunks = ["Third-party software notices\nThese notices cover software distribution, not IP data sources.\n"]
    missing = []
    packages = []
    found_direct = set()
    for group in records.values():
        for record in sorted(group, key=lambda item: (item["name"], item["versions"])):
            name, versions = record["name"], sorted(record["versions"])
            texts = []
            for raw_path in record["paths"]:
                path = Path(raw_path).resolve()
                if not path.is_relative_to(module_root):
                    raise ValueError("package notice path outside installed module tree")
                for file in sorted(path.iterdir()):
                    if file.is_file() and NOTICE.fullmatch(file.name):
                        if file.stat().st_size > 1024 * 1024:
                            raise ValueError("software notice exceeds one MiB")
                        text = file.read_text(encoding="utf-8", errors="strict")
                        if text not in texts:
                            texts.append(text)
            if not texts:
                missing.append({"name": name, "versions": versions, "license": record["license"]})
                continue
            chunks.append("\n" + "=" * 72 + "\n" + name + " " + ", ".join(versions) + "\n")
            chunks.extend(text + "\n" for text in texts)
            packages.append({"name": name, "versions": versions, "license": record["license"]})
            if name in DIRECT:
                (output / DIRECT[name]).write_text("\n\n".join(texts), encoding="utf-8", newline="\n")
                found_direct.add(name)
    if found_direct != set(DIRECT):
        raise ValueError("missing direct runtime software license notice")
    (output / "software.txt").write_text("".join(chunks), encoding="utf-8", newline="\n")
    files = []
    for filename in sorted(set(DIRECT.values()) | {"software.txt"}):
        data = (output / filename).read_bytes()
        files.append({"path": filename, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    manifest = {"format_version": 1, "scope": "software-distribution-notices", "files": files,
                "packages": sorted(packages, key=lambda item: item["name"])}
    (output / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    report = {"scope": "installed-production-dependencies-conservative-superset",
              "copied_packages": len(packages), "missing_packaged_notice": missing,
              "production_notice_review": "pending" if missing else "complete",
              "direct_runtime_notices_complete": True}
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metadata", type=Path, default=ROOT / "build-private/software-license-metadata.json")
    parser.add_argument("--output", type=Path, default=ROOT / "web/public/licenses")
    parser.add_argument("--report", type=Path, default=ROOT / "reports/software-licenses.json")
    args = parser.parse_args()
    report = generate(args.metadata, args.output, args.report)
    print(f"Software notices: {report['copied_packages']} packages copied; direct runtime complete; unresolved package notices remain private")


if __name__ == "__main__":
    main()
