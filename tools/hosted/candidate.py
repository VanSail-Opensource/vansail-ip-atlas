"""Verify an unchanged engineering candidate locally or on an immutable Pages URL.

This verifies frozen preview identity, not production eligibility or performance.
No deployment token, source catalog or private evidence is accepted by this tool.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import hashlib
from itertools import groupby, islice
import json
from pathlib import Path
import re
import sys
import time
import urllib.request
from urllib.parse import unquote, urlsplit

import urllib3

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.release_contract.browser_index import verified_browser_files
from tools.release_contract.contracts import (
    ContractError, canonical_bytes, parse_canonical, rollback_eligible, sha256, tree_inventory, verify_manifest,
)
from tools.release_contract.dataset_credits import validate_credit_tree
from tools.release_contract.data_license import validate_data_license_tree

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
            or report.get("mode") not in ("synthetic", "production") or report.get("production_eligible") is not False
            or not HASH.fullmatch(str(report.get("candidate_bundle_sha256", "")))
            or not HASH.fullmatch(str(report.get("release_id", "")))
            or type(report.get("files")) is not int or type(report.get("bytes")) is not int):
        raise ContractError("a passed source-free frozen candidate report is required")
    if report["mode"] == "production" and not HASH.fullmatch(str(report.get("qualification_receipt_sha256", ""))):
        raise ContractError("production candidate needs its private qualification receipt digest")
    entries, digest = tree_inventory(public)
    if any(path in ("_worker.js", "_routes.json") or path.startswith(("_worker.js/", "functions/")) for path, _, _ in entries):
        raise ContractError("a static candidate cannot contain a Pages runtime")
    if (digest != report["candidate_bundle_sha256"] or len(entries) != report["files"]
            or sum(item[1] for item in entries) != report["bytes"]):
        raise ContractError("candidate tree changed after freezing")
    pointer_bytes = (public / "_atlas/current.json").read_bytes()
    pointer = parse_canonical(pointer_bytes)
    if not isinstance(pointer, dict) or pointer.get("release_id") != report["release_id"]:
        raise ContractError("candidate release differs from report")
    manifest_bytes = (public / "_atlas/releases" / report["release_id"] / "manifest.json").read_bytes()
    manifest = verify_manifest(manifest_bytes, pointer_bytes, now)
    verified_browser_files(public / "_atlas", pointer)
    if manifest["mode"] != report["mode"]:
        raise ContractError("candidate report and manifest modes differ")
    manifests = list((public / "_atlas/releases").glob("*/manifest.json"))
    if not 1 <= len(manifests) <= 2:
        raise ContractError("candidate has too many retained releases")
    objects = {path: (size, digest) for path, size, digest in entries if path.startswith("_atlas/objects/")}
    expected_objects = {}
    release_modes = {}
    for path in manifests:
        retained_bytes = path.read_bytes()
        retained = verify_manifest(retained_bytes, canonical_bytes({
            "format_version": 3, "release_id": path.parent.name,
            "manifest_path": f"/_atlas/releases/{path.parent.name}/manifest.json",
            "manifest_sha256": sha256(retained_bytes)}), now)
        if retained["mode"] != manifest["mode"] or (path.parent.name != manifest["release_id"]
                and not rollback_eligible(retained["valid_from"], retained["valid_until"], now)):
            raise ContractError("retained candidate release is ineligible")
        release_modes[retained["release_id"]] = retained["mode"]
        for obj in retained["objects"]:
            key = f"_atlas/objects/{obj['sha256']}.via3"
            expected = (obj["bytes"], obj["sha256"])
            if objects.get(key) != expected:
                raise ContractError("manifest object is absent or changed")
            expected_objects[key] = expected
    if objects != expected_objects:
        raise ContractError("candidate has unreferenced database objects")
    validate_credit_tree(public, manifest["release_id"], release_modes)
    validate_data_license_tree(public)
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


INVENTORY_WORKERS = 8
READ_CHUNK_BYTES = 64 * 1024


def _inventory_pool(origin):
    options = {"num_pools": 1, "maxsize": INVENTORY_WORKERS, "block": True}
    proxy = urllib.request.getproxies().get("https")
    if proxy and not urllib.request.proxy_bypass(urlsplit(origin).hostname):
        try:
            parsed = urlsplit(proxy if "://" in proxy else "http://" + proxy)
            proxy_headers = {}
            if parsed.username is not None:
                credentials = unquote(parsed.username) + ":" + unquote(parsed.password or "")
                proxy_headers = urllib3.make_headers(proxy_basic_auth=credentials)
            server = parsed._replace(netloc=parsed.netloc.rsplit("@", 1)[-1])
            return urllib3.ProxyManager(server.geturl(), proxy_headers=proxy_headers, **options)
        except (ValueError, urllib3.exceptions.HTTPError):
            raise ContractError("invalid preview HTTPS proxy configuration") from None
    return urllib3.PoolManager(**options)


@contextmanager
def _live_inventory_fetch(origin, deadline):
    # The pool belongs to one verified origin and at most eight simultaneous
    # requests. Explicitly close idle TLS connections, including after failures.
    pool = _inventory_pool(origin)

    def remaining():
        seconds = deadline - time.monotonic()
        if seconds <= 0:
            raise ContractError("preview verification deadline exceeded")
        return seconds

    def fetch(path, size):
        for attempt in range(2):
            try:
                timeout = min(30, remaining())
                response = pool.request("GET", origin + path, headers={
                    "Accept-Encoding": "identity", "User-Agent": QA_USER_AGENT},
                    timeout=timeout, pool_timeout=timeout, preload_content=False, decode_content=False,
                    redirect=False, retries=False)
                try:
                    digest = hashlib.sha256()
                    count = 0
                    while count <= size:
                        read_timeout = min(30, remaining())
                        connection = response.connection
                        if connection is not None and connection.sock is not None:
                            connection.sock.settimeout(read_timeout)
                        block = response.read1(min(READ_CHUNK_BYTES, size + 1 - count))
                        if not block:
                            break
                        count += len(block)
                        digest.update(block)
                    remaining()
                    return response.status, {k.lower(): v for k, v in response.headers.items()}, count, digest.hexdigest()
                finally:
                    # A fully consumed response returns its healthy socket to
                    # the pool. Discard interrupted or oversized responses.
                    response.close()
                    response.release_conn()
            except (urllib3.exceptions.ProtocolError, urllib3.exceptions.TimeoutError):
                # A server can close an idle socket between requests. Start
                # this GET and its digest from byte zero on a fresh connection.
                if attempt:
                    raise ContractError("preview HTTPS transfer interrupted") from None
            except urllib3.exceptions.HTTPError:
                raise ContractError("preview HTTPS connection failed") from None

    try:
        yield fetch
    finally:
        pool.clear()


def verify_preview(public: Path, report: dict, origin: str, now: int, fetch=None, *, production_alias=False) -> dict:
    if production_alias:
        parsed = urlsplit(origin)
        if (report.get("mode") != "production" or parsed.scheme != "https"
                or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.pages\.dev", parsed.netloc)
                or parsed.path or parsed.query or parsed.fragment):
            raise ContractError("post-deployment verification requires the exact HTTPS Pages production origin")
    else:
        origin = check_preview_origin(origin)
    candidate = check_candidate(public, report, now)
    expected_headers = _global_headers(public)
    deadline = time.monotonic() + 600
    if fetch is None:
        with _live_inventory_fetch(origin, deadline) as fetch_digest:
            return _verify_inventory(candidate, report, origin, expected_headers, fetch_digest, deadline, production_alias)

    def fetch_digest(path, size):
        status, headers, data = fetch(path, size)
        return status, headers, len(data), sha256(data)
    return _verify_inventory(candidate, report, origin, expected_headers, fetch_digest, None, production_alias)


def _verify_inventory(candidate, report, origin, expected_headers, fetch_digest, deadline, production_alias):
    live = deadline is not None
    status, headers, _, _ = fetch_digest("/", 64 * 1024)
    if status != 302 or headers.get("location") != "/ip":
        raise ContractError("deployed root is not the required HTTP 302")

    def verify_file(entry):
        path, size, digest = entry
        request_path = "/" + path
        if request_path.endswith("/index.html"):
            request_path = request_path[:-len("index.html")]
        elif request_path.endswith(".html"):
            request_path = request_path[:-len(".html")]
        status, headers, received, received_digest = fetch_digest(request_path, size)
        if (status != 200 and not (path == "404.html" and status == 404)) or received != size or received_digest != digest:
            raise ContractError(f"preview file differs from frozen candidate: {path}")
        for name, value in expected_headers.items():
            if name == "cache-control":
                continue
            if " ".join(headers.get(name, "").split()) != " ".join(value.split()):
                raise ContractError(f"preview effective header differs: {name}")
        cache = {token.strip() for token in headers.get("cache-control", "").lower().split(",")}
        if path.startswith(("_atlas/objects/", "_atlas/browser/", "_atlas/releases/", "_atlas/credits/", "_atlas/legal/", "_nuxt/")):
            if "immutable" not in cache or "max-age=31536000" not in cache:
                raise ContractError("immutable preview object cache policy missing")
        elif path in ("_atlas/current.json", "dataset-credits.json") and ("max-age=0" not in cache or "must-revalidate" not in cache):
            raise ContractError("preview mutable pointer/credit alias revalidation policy missing")
        return 1

    # Pages executes the two control files. The redirect and per-file headers
    # above verify their effects. Only immutable objects and index pages run concurrently.
    entries = (row for row in candidate["entries"] if row[0] not in ("_headers", "_redirects"))
    verified = 0
    with ThreadPoolExecutor(max_workers=INVENTORY_WORKERS) as workers:
        for objects, rows in groupby(entries, key=lambda row: row[0].startswith(("_atlas/objects/","_atlas/browser/"))):
            if live and objects:
                # Keep at most one batch in flight, including after a failed check.
                while batch := tuple(islice(rows, INVENTORY_WORKERS)):
                    verified += sum(workers.map(verify_file, batch))
            else:
                verified += sum(map(verify_file, rows))
    if live and time.monotonic() >= deadline:
        raise ContractError("preview verification deadline exceeded")
    # Fetching all files can cross the release expiry; recheck at completion in live runs.
    if live and time.time() >= candidate["valid_until"]:
        raise ContractError("candidate expired during preview verification")
    return {"scope": "hosted-production-postdeploy-identity" if production_alias else f"hosted-{report['mode']}-preview-identity", "status": "passed", "production_eligible": False,
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
