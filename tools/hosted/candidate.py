"""Verify an unchanged engineering candidate locally or on an immutable Pages URL.

This verifies synthetic preview identity, not production eligibility or performance.
No deployment token, source catalog or private evidence is accepted by this tool.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.release_contract.contracts import (
    ContractError, canonical_bytes, parse_canonical, rollback_eligible, sha256, tree_inventory, verify_manifest,
)

HASH = re.compile(r"[0-9a-f]{64}\Z")
QA_USER_AGENT = "VanSail-IP-Atlas-Preview-QA/1.0 (+https://github.com/VanSail-Opensource/vansail-ip-atlas)"


def check_preview_origin(value: str) -> str:
    """Deployment hash hosts only: mutable branch aliases cannot bind evidence."""
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.netloc
            or not re.fullmatch(r"[0-9a-f]{8,64}\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.pages\.dev", parsed.netloc)
            or parsed.path or parsed.query or parsed.fragment):
        raise ContractError("an immutable HTTPS deployment-hash Pages origin is required")
    return value


def check_candidate(public: Path, report: dict, now: int) -> dict:
    if (not isinstance(report, dict) or report.get("status") != "passed"
            or report.get("mode") != "synthetic" or report.get("production_eligible") is not False
            or not HASH.fullmatch(str(report.get("candidate_bundle_sha256", "")))
            or not HASH.fullmatch(str(report.get("release_id", "")))
            or type(report.get("files")) is not int or type(report.get("bytes")) is not int):
        raise ContractError("a passed source-free synthetic candidate report is required")
    entries, digest = tree_inventory(public)
    if (digest != report["candidate_bundle_sha256"] or len(entries) != report["files"]
            or sum(item[1] for item in entries) != report["bytes"]):
        raise ContractError("candidate tree changed after freezing")
    pointer_bytes = (public / "_atlas/current.json").read_bytes()
    pointer = parse_canonical(pointer_bytes)
    if not isinstance(pointer, dict) or pointer.get("release_id") != report["release_id"]:
        raise ContractError("candidate release differs from report")
    manifest_bytes = (public / "_atlas/releases" / report["release_id"] / "manifest.json").read_bytes()
    manifest = verify_manifest(manifest_bytes, pointer_bytes, now)
    if manifest["mode"] != "synthetic":
        raise ContractError("production cannot use engineering preview evidence")
    manifests = list((public / "_atlas/releases").glob("*/manifest.json"))
    if not 1 <= len(manifests) <= 2:
        raise ContractError("candidate has too many retained releases")
    objects = {path: (size, digest) for path, size, digest in entries if path.startswith("_atlas/objects/")}
    expected_objects = {}
    for path in manifests:
        retained_bytes = path.read_bytes()
        retained = verify_manifest(retained_bytes, canonical_bytes({
            "format_version": 3, "release_id": path.parent.name,
            "manifest_path": f"/_atlas/releases/{path.parent.name}/manifest.json",
            "manifest_sha256": sha256(retained_bytes)}), now)
        if retained["mode"] != "synthetic" or (path.parent.name != manifest["release_id"]
                and not rollback_eligible(retained["valid_from"], retained["valid_until"], now)):
            raise ContractError("retained candidate release is ineligible")
        for obj in retained["objects"]:
            key = f"_atlas/objects/{obj['sha256']}.via3"
            expected = (obj["bytes"], obj["sha256"])
            if objects.get(key) != expected:
                raise ContractError("manifest object is absent or changed")
            expected_objects[key] = expected
    if objects != expected_objects:
        raise ContractError("candidate has unreferenced database objects")
    if (public / "_redirects").read_text(encoding="utf-8").strip() != "/ /ip 302":
        raise ContractError("candidate requires the exact root 302 rule")
    return {"release_id": manifest["release_id"], "valid_until": manifest["valid_until"],
            "candidate_bundle_sha256": digest, "entries": entries}


def _global_headers(public: Path) -> dict[str, str]:
    result = {}
    global_rule = False
    for line in (public / "_headers").read_text(encoding="utf-8").splitlines():
        if line and not line[0].isspace():
            global_rule = line == "/*"
        elif line.strip() and global_rule:
            name, separator, value = line.strip().partition(":")
            if not separator or name.lower() in result:
                raise ContractError("ambiguous candidate response header")
            result[name.lower()] = value.strip()
    if not all(name in result for name in ("content-security-policy", "referrer-policy", "x-content-type-options")):
        raise ContractError("missing candidate security header")
    return result


def verify_preview(public: Path, report: dict, origin: str, now: int, fetch=None) -> dict:
    origin = check_preview_origin(origin)
    candidate = check_candidate(public, report, now)
    expected_headers = _global_headers(public)
    deadline = time.monotonic() + 600
    live = fetch is None
    if fetch is None:
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, request, fp, code, msg, headers, newurl):
                return None
        opener = urllib.request.build_opener(NoRedirect)
        def fetch(path, size):
            if time.monotonic() >= deadline:
                raise ContractError("preview verification deadline exceeded")
            request = urllib.request.Request(origin + path, headers={"Accept-Encoding": "identity", "User-Agent": QA_USER_AGENT})
            try:
                response = opener.open(request, timeout=min(30, max(1, deadline - time.monotonic())))
            except urllib.error.HTTPError as error:
                response = error
            with response:
                # Whole individual responses stay below the existing Pages asset cap.
                return response.status, {k.lower(): v for k, v in response.headers.items()}, response.read(size + 1)
    status, headers, _ = fetch("/", 64 * 1024)
    if status != 302 or headers.get("location") != "/ip":
        raise ContractError("deployed root is not the required HTTP 302")
    verified = 0
    for path, size, digest in candidate["entries"]:
        if path in ("_headers", "_redirects"):
            continue  # Pages executes these files; verify their effects instead.
        request_path = "/" + path
        if request_path.endswith("/index.html"):
            request_path = request_path[:-len("index.html")]
        elif request_path.endswith(".html"):
            request_path = request_path[:-len(".html")]
        status, headers, body = fetch(request_path, size)
        if (status != 200 and not (path == "404.html" and status == 404)) or len(body) != size or sha256(body) != digest:
            raise ContractError(f"preview file differs from frozen candidate: {path}")
        for name, value in expected_headers.items():
            if name == "cache-control":
                continue
            if " ".join(headers.get(name, "").split()) != " ".join(value.split()):
                raise ContractError(f"preview effective header differs: {name}")
        cache = {token.strip() for token in headers.get("cache-control", "").lower().split(",")}
        if path.startswith(("_atlas/objects/", "_atlas/releases/", "_nuxt/")):
            if "immutable" not in cache or "max-age=31536000" not in cache:
                raise ContractError("immutable preview object cache policy missing")
        elif path == "_atlas/current.json" and ("max-age=0" not in cache or "must-revalidate" not in cache):
            raise ContractError("preview pointer revalidation policy missing")
        verified += 1
    # Fetching all files can cross the release expiry; recheck at completion in live runs.
    if live and time.time() >= candidate["valid_until"]:
        raise ContractError("candidate expired during preview verification")
    return {"scope": "hosted-synthetic-preview-identity", "status": "passed", "production_eligible": False,
            "url": origin, "candidate_bundle_sha256": candidate["candidate_bundle_sha256"],
            "release_id": candidate["release_id"], "verified_files": verified,
            "control_files_verified_through_effective_headers_and_redirect": True}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public", type=Path, required=True)
    parser.add_argument("--candidate-report", type=Path, default=Path("reports/static-candidate.json"))
    parser.add_argument("--preview-url")
    parser.add_argument("--report", type=Path, default=Path("reports/preview-identity.json"))
    args = parser.parse_args()
    try:
        candidate_report = json.loads(args.candidate_report.read_text(encoding="utf-8"))
        now = int(time.time())
        if args.preview_url:
            result = verify_preview(args.public, candidate_report, args.preview_url, now)
            if args.report.resolve().is_relative_to(args.public.resolve()):
                raise ContractError("preview evidence must remain outside the frozen public tree")
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
            print(f"PASS: {result['verified_files']} deployed files match the exact engineering candidate")
        else:
            check_candidate(args.public, candidate_report, now)
            print("PASS: unchanged engineering candidate; production remains blocked")
        return 0
    except (ContractError, OSError, ValueError) as error:
        print(f"FAIL: candidate identity: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
