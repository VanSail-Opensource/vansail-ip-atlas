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
CODE_ASSET = re.compile(r"\.(?:m?js|css|wasm)$")


def review_bundle(audit_path: Path, public: Path) -> dict:
    """Verify exact emitted code bytes before using a private ancestry exclusion."""
    raw = audit_path.read_bytes()
    if len(raw) > 16 * 1024 * 1024:
        raise ValueError("software bundle audit exceeds sixteen MiB")
    audit = json.loads(raw)
    if (not isinstance(audit, dict) or set(audit) != {"format_version", "scope", "client", "workers"}
            or audit["format_version"] != 1 or audit["scope"] != "exact-client-and-worker-module-ancestry"
            or not isinstance(audit["workers"], list) or len(audit["workers"]) > 64):
        raise ValueError("invalid software bundle audit")
    packages: dict[str, set[str]] = {}
    assets = {}
    worker_hashes = []
    for number, bundle in enumerate([audit["client"], *audit["workers"]]):
        if (not isinstance(bundle, dict) or set(bundle) != {"modules", "assets"}
                or not isinstance(bundle["modules"], list) or len(bundle["modules"]) > 100000
                or not isinstance(bundle["assets"], list) or len(bundle["assets"]) >= 18500):
            raise ValueError("invalid software module ancestry")
        seen = set()
        for module in bundle["modules"]:
            if (not isinstance(module, dict) or set(module) != {"id", "package", "version", "rendered_bytes"}
                    or not isinstance(module["id"], str) or len(module["id"]) > 8192 or module["id"] in seen
                    or not isinstance(module["rendered_bytes"], int) or module["rendered_bytes"] < 0):
                raise ValueError("invalid software module identity")
            seen.add(module["id"])
            name, version = module["package"], module["version"]
            if name is None:
                if version is not None or "/node_modules/" in "/" + module["id"].replace("\\", "/"):
                    raise ValueError("unclassified installed module in software audit")
                continue
            if (not isinstance(name, str) or not re.fullmatch(r"(?:@[a-z0-9_.-]+/)?[a-z0-9_.-]+", name)
                    or not isinstance(version, str) or not re.fullmatch(r"[0-9A-Za-z.+_-]{1,100}", version)):
                raise ValueError("invalid software package version")
            packages.setdefault(name, set()).add(version)
        for asset in bundle["assets"]:
            if (not isinstance(asset, dict) or set(asset) != {"path", "bytes", "sha256"}
                    or not isinstance(asset["path"], str) or not CODE_ASSET.search(asset["path"])
                    or not re.fullmatch(r"[0-9a-f]{64}", asset["sha256"])
                    or not isinstance(asset["bytes"], int) or asset["bytes"] < 0):
                raise ValueError("invalid software code asset")
            if number:
                worker_hashes.append(asset["sha256"])
                continue
            path = Path(asset["path"])
            if path.is_absolute() or ".." in path.parts or "\\" in asset["path"] or asset["path"] in assets:
                raise ValueError("unsafe or duplicate software code asset")
            data = (public / path).read_bytes()
            if len(data) != asset["bytes"] or hashlib.sha256(data).hexdigest() != asset["sha256"]:
                raise ValueError("software bundle audit does not match emitted bytes")
            assets[asset["path"]] = asset["sha256"]
    actual = {p.relative_to(public).as_posix() for p in public.rglob("*") if p.is_file() and CODE_ASSET.search(p.name)}
    if not assets or set(assets) != actual or any(h not in assets.values() for h in worker_hashes):
        raise ValueError("software audit does not cover the complete client/worker code tree")
    return {"audit_sha256": hashlib.sha256(raw).hexdigest(), "verified_code_assets": len(assets),
            "packages": [{"name": name, "versions": sorted(versions)} for name, versions in sorted(packages.items())]}


def generate(metadata: Path, output: Path, report_path: Path, bundle_audit: Path | None = None, public: Path | None = None) -> dict:
    metadata_bytes = metadata.read_bytes()
    if len(metadata_bytes) > 16 * 1024 * 1024:
        raise ValueError("installed software metadata exceeds sixteen MiB")
    # json.loads(bytes) also handles PowerShell's UTF-16 BOM redirection. Hosted
    # Linux pnpm output is UTF-8; neither representation changes package facts.
    records = json.loads(metadata_bytes)
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
              "metadata_sha256": hashlib.sha256(metadata_bytes).hexdigest(),
              "copied_packages": len(packages), "missing_packaged_notice": missing,
              "production_notice_review": "pending" if missing else "complete",
              "direct_runtime_notices_complete": True}
    if bundle_audit is not None:
        review = review_bundle(bundle_audit, public or ROOT / "web/.output/public")
        copied = {(p["name"], version) for p in packages if p["license"] != "Unknown" for version in p["versions"]}
        observed = {(p["name"], version) for p in review["packages"] for version in p["versions"]}
        unresolved = [{"name": name, "version": version} for name, version in sorted(observed - copied)]
        excluded = [p for p in missing if all((p["name"], version) not in observed for version in p["versions"])]
        report.update({"scope": "installed-dependency-superset-with-exact-client-worker-review",
                       "bundle_review": review, "excluded_from_client_and_worker": excluded,
                       "unresolved_runtime_notices": unresolved,
                       "production_notice_review": "pending" if unresolved else "complete"})
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metadata", type=Path, default=ROOT / "build-private/software-license-metadata.json")
    parser.add_argument("--output", type=Path, default=ROOT / "web/public/licenses")
    parser.add_argument("--report", type=Path, default=ROOT / "reports/software-licenses.json")
    parser.add_argument("--bundle-audit", type=Path, help="private actual client/worker module ancestry, bound to emitted code hashes")
    parser.add_argument("--public", type=Path, default=ROOT / "web/.output/public")
    parser.add_argument("--require-runtime-review", action="store_true")
    args = parser.parse_args()
    report = generate(args.metadata, args.output, args.report, args.bundle_audit, args.public)
    print(f"Software notices: {report['copied_packages']} packages copied; runtime review {report['production_notice_review']}")
    if args.require_runtime_review and (args.bundle_audit is None or report["production_notice_review"] != "complete"):
        raise SystemExit("runtime software notice review is incomplete")


if __name__ == "__main__":
    main()
