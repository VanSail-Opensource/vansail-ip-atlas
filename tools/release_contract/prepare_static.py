"""Verify a synthetic immutable atlas, include it in Nuxt's tree and freeze CSP.

Production remains default-deny. This local packaging tool does not deploy files.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import struct
import sys
import tempfile
import threading
import time

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.release_contract.contracts import (
    ContractError, canonical_bytes, parse_canonical, rollback_eligible,
    scan_frontend_text, scan_public_records, sha256, tree_inventory, verify_manifest,
)
from tools.release_contract.nuxt_timestamps import canonicalize_operational_times

ROOT = Path(__file__).resolve().parents[2]
INLINE_SCRIPT = re.compile(r"<script\b([^>]*)>([\s\S]*?)</script\s*>", re.IGNORECASE)
MAX_PUBLIC_DECODED = 32 * 1024 * 1024


def known_private_values() -> tuple[str, ...]:
    from tools.atlas_contracts.config import load_yaml
    values = set()
    catalog = load_yaml(ROOT / "configs/sources.yaml")
    for entry in catalog["sources"]:
        for key in ("id", "evidence_family", "source_group"):
            if isinstance(entry.get(key), str):
                values.add(entry[key])
        for parent, key in (("download", "url"), ("license", "evidence_url"), ("publication_proof", "locator")):
            value = entry.get(parent, {}).get(key)
            if isinstance(value, str) and len(value) >= 8:
                values.add(value)
    return tuple(sorted(values))


def _check_tree_path(path: Path, *, must_exist=True) -> Path:
    if path.is_symlink() or (must_exist and not path.is_dir()):
        raise ContractError("expected real directory")
    return path.resolve()


def verify_atlas(atlas: Path, now: int) -> dict:
    atlas = _check_tree_path(atlas)
    pointer_path = atlas / "current.json"
    if pointer_path.is_symlink() or not pointer_path.is_file():
        raise ContractError("missing safe current pointer")
    pointer_bytes = pointer_path.read_bytes()
    pointer = parse_canonical(pointer_bytes)
    release_id = pointer.get("release_id") if isinstance(pointer, dict) else None
    if not isinstance(release_id, str) or not re.fullmatch(r"[0-9a-f]{64}", release_id):
        raise ContractError("invalid current release id")
    current_path = atlas / "releases" / release_id / "manifest.json"
    if current_path.is_symlink() or not current_path.is_file():
        raise ContractError("missing safe current manifest")
    current = verify_manifest(current_path.read_bytes(), pointer_bytes, now)
    if current["mode"] != "synthetic":
        raise ContractError("production packaging requires unimplemented full capability and approval gates")
    expected = {"current.json"}
    manifests = list((atlas / "releases").glob("*/manifest.json"))
    if not 1 <= len(manifests) <= 2:
        raise ContractError("only current and immediate previous eligible manifests allowed")
    objects = {}
    for path in manifests:
        if path.is_symlink() or not re.fullmatch(r"[0-9a-f]{64}", path.parent.name):
            raise ContractError("unsafe retained manifest")
        manifest_bytes = path.read_bytes()
        retained_pointer = canonical_bytes({"format_version": 3, "release_id": path.parent.name,
            "manifest_path": f"/_atlas/releases/{path.parent.name}/manifest.json",
            "manifest_sha256": sha256(manifest_bytes)})
        manifest = verify_manifest(manifest_bytes, retained_pointer, now)
        if manifest["mode"] != "synthetic":
            raise ContractError("synthetic candidate cannot retain production data")
        if path.parent.name != release_id and not rollback_eligible(manifest["valid_from"], manifest["valid_until"], now):
            raise ContractError("retained generation is ineligible for rollback")
        expected.add(path.relative_to(atlas).as_posix())
        for obj in manifest["objects"]:
            filename = f"objects/{obj['sha256']}.via3"
            if filename in objects and objects[filename] != obj:
                raise ContractError("conflicting retained object metadata")
            objects[filename] = obj
            expected.add(filename)
    actual_entries, _ = tree_inventory(atlas)
    if {entry[0] for entry in actual_entries} != expected:
        raise ContractError("atlas contains missing, private or unreferenced extra files")
    for name, size, digest in actual_entries:
        if name.startswith("objects/"):
            if objects[name]["bytes"] != size or objects[name]["sha256"] != digest:
                raise ContractError("object bytes/hash mismatch")
            preflight_public_object(atlas / name)
    return {"release_id": release_id, "object_count": len(objects), "mode": current["mode"], "valid_from": current["valid_from"],
            "valid_until": current["valid_until"]}


def preflight_public_object(path: Path) -> int:
    """Small header/table reads enforce deployment admission before Go decoding."""
    with path.open("rb") as source:
        header = source.read(64)
        if len(header) != 64 or header[:4] != b"VIA3":
            raise ContractError("invalid object framing")
        count = struct.unpack_from("<I", header, 16)[0]
        table_offset = struct.unpack_from("<Q", header, 20)[0]
        declared = struct.unpack_from("<Q", header, 36)[0]
        if not 1 <= count <= 256 or table_offset != 64 or declared > MAX_PUBLIC_DECODED:
            raise ContractError("public object exceeds browser deployment profile")
        table = source.read(count * 64)
        if len(table) != count * 64:
            raise ContractError("truncated object section table")
        decoded = sum(struct.unpack_from("<Q", table, offset + 24)[0] for offset in range(0, len(table), 64))
        if decoded != declared or decoded > MAX_PUBLIC_DECODED:
            raise ContractError("public object exceeds browser deployment profile")
        return decoded


def inspect_binary(atlas: Path, private_values: tuple[str, ...] = ()) -> int:
    """Bounded NDJSON supplied by the actual Go reader, with no shell execution."""
    command = ["go", "run", "./cmd/atlas", "inspect", "-public", "-dir", str(atlas / "objects")]
    process = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    timer = threading.Timer(180, process.kill)
    timer.start()
    count = 0
    try:
        assert process.stdout is not None
        while True:
            line = process.stdout.readline(64 * 1024 * 1024 + 1)
            if not line:
                break
            if len(line) > 64 * 1024 * 1024:
                raise ContractError("binary inspection record exceeds bounds")
            try:
                entry = json.loads(line)
            except (UnicodeError, json.JSONDecodeError) as error:
                raise ContractError("invalid binary inspection record") from error
            # Temporarily accept one aggregate JSON array for the P1 Go tool;
            # each individual string table is still required to pass the scanner.
            rows = entry if isinstance(entry, list) else [entry]
            for row in rows:
                if (not isinstance(row, dict) or not isinstance(row.get("strings"), list)
                        or type(row.get("kind")) is not int or not 1 <= row["kind"] <= 14
                        or type(row.get("decoded_bytes")) is not int or not 0 <= row["decoded_bytes"] <= MAX_PUBLIC_DECODED):
                    raise ContractError("invalid binary inspection schema")
                scan_public_records(row["strings"], private_values)
                count += 1
        if process.wait() != 0:
            raise ContractError("Go binary validation failed")
    finally:
        timer.cancel()
        if process.poll() is None:
            process.kill()
        process.wait()
        if process.stdout is not None:
            process.stdout.close()
    return count


def freeze_csp(public: Path) -> int:
    hashes = set()
    for path in public.rglob("*.html"):
        text = path.read_text(encoding="utf-8", errors="strict")
        if re.search(r"\bon[a-z]+\s*=", text, re.IGNORECASE):
            raise ContractError("inline HTML event handlers are forbidden")
        for attributes, body in INLINE_SCRIPT.findall(text):
            if re.search(r"\bsrc\s*=", attributes, re.IGNORECASE):
                continue
            mime = re.search(r'\btype\s*=\s*[\"\']([^\"\']+)', attributes, re.IGNORECASE)
            if mime and mime.group(1).lower() in ("application/json", "application/ld+json"):
                continue  # Inert hydration data is scanned but not executable JS.
            if body:
                hashes.add("'sha256-" + base64.b64encode(hashlib.sha256(body.encode()).digest()).decode() + "'")
    headers_path = public / "_headers"
    headers = headers_path.read_text(encoding="utf-8")
    if "Content-Security-Policy:" not in headers or "script-src" not in headers:
        raise ContractError("missing static CSP template")
    if "'unsafe-eval'" in headers or "script-src 'self' 'unsafe-inline'" in headers:
        raise ContractError("unsafe script CSP")
    script_policy = "script-src 'self'" + (" " + " ".join(sorted(hashes)) if hashes else "")
    headers, replacements = re.subn(r"script-src\s+[^;\r\n]+", script_policy, headers)
    if replacements != 1:
        raise ContractError("ambiguous CSP template")
    headers_path.write_text(headers, encoding="utf-8", newline="\n")
    return len(hashes)


def scan_frontend(public: Path, private_values: tuple[str, ...] = ()) -> None:
    for path in public.rglob("*"):
        if not path.is_file() or "_atlas" in path.relative_to(public).parts:
            continue
        if path.suffix == ".map" or path.name in ("sources.yaml", "descriptor.json"):
            raise ContractError("private artifact in static tree")
        if path.suffix in (".html", ".js", ".mjs", ".css", ".json", ".svg") or path.name in ("_headers", "_redirects"):
            text = path.read_text(encoding="utf-8", errors="strict")
            scan_frontend_text(text, private_values)
            if path.suffix == ".json":
                if path.relative_to(public).as_posix() == "licenses/manifest.json":
                    verify_software_notices(public)
                else:
                    scan_public_records(json.loads(text), private_values)


def verify_software_notices(public: Path) -> None:
    directory = public / "licenses"
    if not directory.exists():
        return  # Minimal package unit fixtures need no bundled application code.
    manifest_path = directory / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if (not isinstance(manifest, dict) or set(manifest) != {"format_version", "scope", "files", "packages"}
            or manifest.get("format_version") != 1 or manifest.get("scope") != "software-distribution-notices"
            or not isinstance(manifest["files"], list) or not isinstance(manifest["packages"], list)):
        raise ContractError("invalid software notice inventory")
    expected = {"manifest.json"}
    for entry in manifest["files"]:
        if not isinstance(entry, dict) or set(entry) != {"path", "bytes", "sha256"}:
            raise ContractError("invalid software notice entry")
        filename = entry["path"]
        if not isinstance(filename, str) or not re.fullmatch(r"[a-z0-9-]+\.txt", filename) or filename in expected:
            raise ContractError("unsafe or duplicate software notice path")
        expected.add(filename)
        data = (directory / filename).read_bytes()
        if len(data) != entry["bytes"] or sha256(data) != entry["sha256"]:
            raise ContractError("software license notice was mutated")
    if {path.name for path in directory.iterdir()} != expected:
        raise ContractError("unaccounted software notice files")
    for package in manifest["packages"]:
        if (not isinstance(package, dict) or set(package) != {"name", "versions", "license"}
                or not isinstance(package["name"], str) or len(package["name"]) > 214
                or not re.fullmatch(r"(?:@[A-Za-z0-9._-]+/)?[A-Za-z0-9._-]+", package["name"])
                or not isinstance(package["versions"], list) or not package["versions"]
                or any(not isinstance(version, str) or not re.fullmatch(r"[0-9][0-9A-Za-z.+_-]{0,100}", version) for version in package["versions"])
                or not isinstance(package["license"], str)
                or not re.fullmatch(r"[A-Za-z0-9 .()+/_-]{1,200}", package["license"])):
            raise ContractError("invalid software package identity")


def prepare(atlas: Path, public: Path, now: int) -> dict:
    atlas, public = _check_tree_path(atlas), _check_tree_path(public)
    if atlas == public or atlas in public.parents or public in atlas.parents:
        raise ContractError("atlas input and generated public tree must be separate")
    metadata = verify_atlas(atlas, now)
    private_values = known_private_values()
    inspected = inspect_binary(atlas, private_values)
    if inspected != metadata["object_count"]:
        raise ContractError("binary scanner did not validate every object")
    target = public / "_atlas"
    if target.is_symlink():
        raise ContractError("atlas destination cannot be a symlink")
    # Stage outside the deploy tree. Every recursive cleanup target is verified
    # against this exact generated-output parent before any removal.
    stage = Path(tempfile.mkdtemp(prefix="atlas-stage-", dir=public.parent)).resolve()
    previous = None
    try:
        shutil.copytree(atlas, stage / "_atlas")
        verify_atlas(stage / "_atlas", now)
        if target.exists():
            previous = stage / "previous"
            os.replace(target, previous)
        os.replace(stage / "_atlas", target)
        normalized_timestamps = canonicalize_operational_times(public, metadata["valid_from"])
        hashes = freeze_csp(public)
        verify_software_notices(public)
        scan_frontend(public, private_values)
        entries, digest = tree_inventory(public)
        return {**metadata, "status": "passed", "scope": "local-synthetic-static-candidate",
                "candidate_bundle_sha256": digest, "files": len(entries), "bytes": sum(item[1] for item in entries),
                "framework_operational_timestamps_normalized": normalized_timestamps,
                "inline_script_hashes": hashes, "hosted_acceptance": "pending", "production_eligible": False}
    except BaseException:
        if previous is not None and previous.exists():
            if target.exists():
                failed = stage / "failed"
                os.replace(target, failed)
            os.replace(previous, target)
        raise
    finally:
        if stage.parent != public.parent.resolve() or not stage.name.startswith("atlas-stage-"):
            raise ContractError("unsafe cleanup target")
        shutil.rmtree(stage)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--atlas", type=Path, required=True)
    parser.add_argument("--public", type=Path, default=ROOT / "web/.output/public")
    parser.add_argument("--now", type=int, default=int(time.time()))
    parser.add_argument("--report", type=Path, default=ROOT / "reports/static-candidate.json")
    args = parser.parse_args()
    try:
        if args.report.resolve().is_relative_to(args.public.resolve()):
            raise ContractError("candidate reports must remain outside the public tree")
        report = prepare(args.atlas, args.public, args.now)
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"PASS: complete local synthetic candidate; {report['files']} files; production blocked")
        return 0
    except (ContractError, OSError, ValueError) as error:
        print(f"FAIL: static candidate: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
