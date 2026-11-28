"""Bounded Pages Direct Upload of a frozen candidate; never rebuild or approve.

Preview uploads need qualified production input receipts. Production additionally
requires the complete trusted acceptance packet and explicit exact-artifact
approval, rechecked immediately before creating the deployment. Credentials and
ephemeral asset JWTs are never printed, serialized or written to disk.
"""
from __future__ import annotations

import argparse
import base64
from email.utils import parsedate_to_datetime
import hashlib
import http.client
import json
import math
import mimetypes
import os
from pathlib import Path
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request
import uuid

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.hosted.candidate import check_candidate, verify_preview
from tools.release_contract.contracts import ContractError, parse_canonical, rollback_eligible, sha256, tree_inventory
from tools.release_contract.pages_failures import failure_marker
from tools.release_contract.production import qualify_public, read_private
from tools.release_contract.prepare_static import inspect_binary, known_private_values, scan_frontend, verify_atlas
from tools.release_contract.promotion import approve, automatic, json_object

API = "https://api.cloudflare.com/client/v4"
# Cloudflare workers-sdk/packages/wrangler/src/pages/constants.ts sets both
# limits on decoded assets. check_candidate enforces the project's stricter
# per-file and whole-tree limits before uploading anything.
UPLOAD_BUCKET_BYTES = 40 * 1024 * 1024
UPLOAD_BUCKET_FILES = 1000 if os.name == "nt" else 2000
ASSET_HASH_BATCH = 1000
ASSET_ROUTES = {"/pages/assets/check-missing", "/pages/assets/upload", "/pages/assets/upsert-hashes"}
MAX_ASSET_ATTEMPTS = 5
TRANSIENT_HTTP = {408, 429, 500, 502, 503, 504, 520, 521, 522, 523, 524}
DEPLOYMENT_ID = r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"


class PagesProgress:
    phase = "arguments"


class PagesRequestFailure(ContractError):
    def __init__(self, classification):
        super().__init__("Pages API request did not satisfy its contract")
        self.classification = classification


def _network_class(error):
    reason = error.reason if isinstance(error, urllib.error.URLError) else error
    if isinstance(reason, socket.gaierror):
        return "network-dns"
    if isinstance(reason, TimeoutError):
        return "network-timeout"
    if isinstance(reason, ssl.SSLError):
        return "network-tls"
    if isinstance(reason, (http.client.IncompleteRead, http.client.RemoteDisconnected)):
        return "network-interrupted"
    if isinstance(reason, ConnectionError):
        return "network-connection"
    if isinstance(reason, http.client.HTTPException):
        return "network-protocol"
    return "network-other"


def _failure_identity(value, pattern):
    return value if isinstance(value, str) and re.fullmatch(pattern, value) else None


def _transient_network(error):
    reason = error.reason if isinstance(error, urllib.error.URLError) else error
    if isinstance(reason, socket.gaierror):
        return reason.errno == socket.EAI_AGAIN
    return isinstance(reason, (TimeoutError, ConnectionError, ssl.SSLEOFError, http.client.IncompleteRead))


def _retry_delay(header, backoff):
    if header is None:
        return backoff
    if re.fullmatch(r"[0-9]{1,2}", header):
        wait = int(header)
    else:
        try:
            date = parsedate_to_datetime(header)
            if date.tzinfo is None:
                return None
            wait = math.ceil(date.timestamp() - time.time())
        except (ValueError, TypeError, OverflowError, OSError):
            return None
    return max(backoff, wait) if wait <= 30 else None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


class Pages:
    def __init__(self, account: str, project: str, token: str, *, progress: PagesProgress | None = None):
        if (not re.fullmatch(r"[0-9a-f]{32}", account)
                or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,56}[a-z0-9])?", project)
                or not isinstance(token, str) or not token.isascii() or not 20 <= len(token) <= 4096
                or any(ord(ch) <= 32 or ord(ch) == 127 for ch in token)):
            raise ContractError("valid scoped Pages account/project credentials required")
        self.project = project
        self.prefix = f"/accounts/{account}/pages/projects/{project}"
        self._token = token
        self._opener = urllib.request.build_opener(NoRedirect)
        self.progress = progress if progress is not None else PagesProgress()

    def request(self, path: str, *, method="GET", value=None, body=None, content_type="application/json", asset_token=None):
        if path != self.prefix and not path.startswith(self.prefix + "/") and path not in ASSET_ROUTES:
            raise ContractError("unsupported Pages API route")
        if any(ch in path for ch in "?#\\") or ".." in path.split("/"):
            raise ContractError("unsafe Pages API route")
        payload = json.dumps(value, separators=(",", ":")).encode() if value is not None else body
        token = asset_token or self._token
        request = urllib.request.Request(API + path, data=payload, method=method,
            headers={"Authorization": "Bearer " + token, "Content-Type": content_type,
                     "User-Agent": "VanSail-IP-Atlas-Release/1.0"})
        # A lost response to a deployment or rollback may follow a committed
        # mutation. Only time-bounded retries of content-keyed asset calls are safe.
        attempts = MAX_ASSET_ATTEMPTS if method == "POST" and path in ASSET_ROUTES else 1
        for attempt in range(attempts):
            delay = 2 ** attempt
            try:
                with self._opener.open(request, timeout=60) as response:
                    data = response.read(2 * 1024 * 1024 + 1)
                    # A bounded read may return a short body without raising
                    # IncompleteRead even when Content-Length promised more.
                    if len(data) <= 2 * 1024 * 1024 and response.length:
                        raise http.client.IncompleteRead(b"")
                break
            except urllib.error.HTTPError as error:
                # Expose only a conventional HTTP status. Never stringify the
                # exception, request URL, response body or retry headers.
                code = error.code
                classification = f"http-{code}" if type(code) is int and 100 <= code <= 599 else "http-error"
                retry = error.code in TRANSIENT_HTTP
                header = error.headers.get("Retry-After") if error.headers else None
                error.close()
                delay = _retry_delay(header, delay)
                retry = retry and delay is not None
            except (OSError, http.client.HTTPException) as error:
                classification = _network_class(error)
                retry = _transient_network(error)
            if not retry or attempt + 1 == attempts:
                raise PagesRequestFailure(classification) from None
            time.sleep(delay)
        if len(data) > 2 * 1024 * 1024:
            raise PagesRequestFailure("response")
        try:
            result = json_object(data)
        except ValueError:
            raise PagesRequestFailure("response") from None
        if result.get("success") is not True:
            raise PagesRequestFailure("response")
        return result.get("result")

    def _asset_upload_token(self) -> str:
        self.progress.phase = "asset-token"
        result = self.request(self.prefix + "/upload-token")
        if not isinstance(result, dict) or not isinstance(result.get("jwt"), str):
            raise ContractError("ephemeral Pages asset credential unavailable")
        jwt = result["jwt"]
        if not jwt.isascii() or not 20 <= len(jwt) <= 8192 or any(ord(ch) <= 32 or ord(ch) == 127 for ch in jwt):
            raise ContractError("invalid ephemeral Pages asset credential")
        return jwt

    def _missing_assets(self, keys: list[str], jwt: str) -> list[str]:
        missing = []
        self.progress.phase = "asset-check"
        for index in range(0, len(keys), ASSET_HASH_BATCH):
            requested = keys[index:index + ASSET_HASH_BATCH]
            absent = self.request("/pages/assets/check-missing", method="POST", value={"hashes": requested}, asset_token=jwt)
            if (not isinstance(absent, list) or any(not isinstance(key, str) or key not in requested for key in absent)
                    or len(absent) != len(set(absent))):
                raise ContractError("invalid Pages missing-asset response")
            missing.extend(absent)
        return missing

    def upload_assets(self, public: Path, candidate: dict) -> dict[str, str]:
        self.progress.phase = "asset-preflight"
        verified = check_candidate(public, candidate, int(time.time()))
        jwt = self._asset_upload_token()
        self.progress.phase = "asset-hashes"
        manifest, assets = {}, {}
        for relative, size, digest in verified["entries"]:
            if relative in ("_headers", "_redirects"):
                continue
            # Pages accepts content keys with extension-dependent MIME identity.
            content_key, file_hash = hashlib.sha256(), hashlib.sha256()
            with (public / relative).open("rb") as source:
                while chunk := source.read(1024 * 1024):
                    content_key.update(chunk); file_hash.update(chunk)
            if file_hash.hexdigest() != digest:
                raise ContractError("frozen asset changed before hash preparation")
            content_key.update(Path(relative).suffix.encode("ascii"))
            key = content_key.hexdigest()[:32]
            existing = assets.get(key)
            if existing is not None and existing[2] != digest:
                raise ContractError("Pages content key collision")
            manifest["/" + relative] = key
            assets[key] = (relative, size, digest)
        keys = sorted(assets)
        missing = self._missing_assets(keys, jwt)
        self.progress.phase = "asset-upload"
        batch, batch_size = [], 0
        def flush():
            nonlocal batch, batch_size
            if batch:
                self.request("/pages/assets/upload", method="POST", value=batch, asset_token=jwt)
                batch, batch_size = [], 0
        for key in missing:
            relative, size, digest = assets[key]
            if len(batch) == UPLOAD_BUCKET_FILES or batch_size + size > UPLOAD_BUCKET_BYTES:
                flush()
            data = (public / relative).read_bytes()
            if len(data) != size or sha256(data) != digest:
                raise ContractError("frozen asset changed before upload")
            content = base64.b64encode(data).decode("ascii")
            mime = "application/javascript" if relative.endswith((".js", ".mjs")) else mimetypes.guess_type(relative)[0] or "application/octet-stream"
            batch.append({"key": key, "base64": True, "value": content, "metadata": {"contentType": mime}})
            batch_size += size
        flush()
        self.progress.phase = "asset-upsert"
        try:
            for index in range(0, len(keys), ASSET_HASH_BATCH):
                self.request("/pages/assets/upsert-hashes", method="POST",
                             value={"hashes": keys[index:index + ASSET_HASH_BATCH]}, asset_token=jwt)
        except PagesRequestFailure as error:
            if error.classification != "http-400":
                raise
            # Wrangler treats refresh as advisory for the next upload. Accept
            # its rejection only after a fresh, affirmative presence check for
            # the complete manifest, not merely the rejected refresh batch.
            if self._missing_assets(keys, self._asset_upload_token()):
                raise ContractError("Pages asset presence could not be confirmed") from None
            print("Pages advisory asset hash refresh was rejected. All staged asset keys were confirmed present.",
                  file=sys.stderr, flush=True)
        self.progress.phase = "asset-final-check"
        check_candidate(public, candidate, int(time.time()))
        return manifest

    def create(self, public: Path, candidate: dict, manifest: dict, branch: str, head: str) -> dict:
        self.progress.phase = "deployment-create"
        boundary = "atlas-" + uuid.uuid4().hex
        fields = {"manifest": json.dumps(manifest, separators=(",", ":")).encode(), "branch": branch.encode(),
                  "commit_hash": head.encode(), "commit_message": ("atlas:" + candidate["candidate_bundle_sha256"]).encode(),
                  "commit_dirty": b"false"}
        parts = []
        for name, data in fields.items():
            parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n".encode() + data + b"\r\n")
        for name in ("_headers", "_redirects"):
            data = (public / name).read_bytes()
            if len(data) > 1024 * 1024:
                raise ContractError("Pages control file exceeds bound")
            parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"{name}\"\r\nContent-Type: text/plain\r\n\r\n".encode() + data + b"\r\n")
        parts.append(f"--{boundary}--\r\n".encode())
        result = self.request(self.prefix + "/deployments", method="POST", body=b"".join(parts),
                              content_type="multipart/form-data; boundary=" + boundary)
        if not isinstance(result, dict):
            raise ContractError("Pages deployment creation returned no identity")
        self.created_deployment_id = result.get("id")
        return self.wait(result["id"], candidate["valid_until"])

    def wait(self, deployment_id: str, expires: int) -> dict:
        self.progress.phase = "deployment-wait"
        if not re.fullmatch(DEPLOYMENT_ID, str(deployment_id)):
            raise ContractError("invalid Pages deployment identity")
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline and time.time() < expires:
            value = self.request(self.prefix + "/deployments/" + deployment_id)
            status = value.get("latest_stage", {}).get("status")
            if status == "success" and value.get("latest_stage", {}).get("name") == "deploy":
                return value
            if status in ("failure", "canceled"):
                raise ContractError("Pages deployment failed")
            time.sleep(2)
        raise ContractError("Pages deployment verification timed out or candidate expired")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("preview", "promote", "rollback"))
    parser.add_argument("--public", type=Path, required=True)
    parser.add_argument("--candidate-report", type=Path, default=Path("reports/static-candidate.json"))
    parser.add_argument("--qualification-receipt", type=Path, action="append", required=True)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--approval", type=Path)
    parser.add_argument("--automatic", action="store_true")
    parser.add_argument("--deployment-id")
    parser.add_argument("--account", required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--report", type=Path, default=Path("reports/pages-deployment.json"))
    args = parser.parse_args()
    client, candidate = None, None
    progress = PagesProgress()
    try:
        if not re.fullmatch(r"[0-9a-f]{40}", args.head) or args.report.resolve().is_relative_to(args.public.resolve()):
            raise ContractError("invalid deployment revision or report location")
        progress.phase = "candidate"
        candidate = json_object(read_private(args.candidate_report))
        check_candidate(args.public, candidate, int(time.time()))
        if candidate["mode"] != "production":
            raise ContractError("production workflow cannot upload synthetic data")
        progress.phase = "qualification"
        qualify_public(args.public, candidate, args.qualification_receipt, int(time.time()))
        progress.phase = "atlas-validation"
        atlas = verify_atlas(args.public / "_atlas", int(time.time()), production=True, credits=True)
        progress.phase = "binary-inspection"
        private_values = known_private_values()
        if inspect_binary(args.public / "_atlas", private_values) != atlas["object_count"]:
            raise ContractError("Pages candidate binary scanner did not inspect all objects")
        progress.phase = "frontend-inspection"
        scan_frontend(args.public, private_values)
        def authorization():
            progress.phase = "authorization"
            if not args.evidence or not (args.approval or args.automatic):
                raise ContractError("production promotion requires exact evidence and explicit approval")
            from tools.atlas_contracts.config import load_yaml
            evidence = read_private(args.evidence)
            if parse_canonical(evidence)["head_sha"] != args.head:
                raise ContractError("deployment revision differs from approved evidence")
            if args.automatic:
                if args.approval:
                    raise ContractError('automatic and manual authorization cannot be combined')
                return automatic(args.public, args.qualification_receipt, evidence, int(time.time()), rollback=args.operation == 'rollback')
            return approve(args.public, args.qualification_receipt, evidence, load_yaml(args.approval), int(time.time()))
        if args.operation != "preview":
            authorization()
        progress.phase = "credentials"
        client = Pages(args.account, args.project, os.environ.get("CLOUDFLARE_API_TOKEN", ""), progress=progress)
        progress.phase = "project"
        project = client.request(client.prefix)
        production_branch = project.get("production_branch")
        if not isinstance(production_branch, str) or not production_branch:
            raise ContractError("Pages production branch unavailable")
        if args.operation == "rollback":
            progress.phase = "rollback-target"
            if not rollback_eligible(candidate["valid_from"], candidate["valid_until"], int(time.time())):
                raise ContractError("original approved release is no longer rollback eligible")
            if not re.fullmatch(r"[0-9a-f-]{36}", str(args.deployment_id)):
                raise ContractError("explicit eligible production rollback deployment required")
            deployment = client.request(client.prefix + "/deployments/" + args.deployment_id)
            metadata = deployment.get("deployment_trigger", {}).get("metadata", {})
            if (deployment.get("environment") != "production" or metadata.get("commit_hash") != args.head
                    or metadata.get("commit_message") != "atlas:" + candidate["candidate_bundle_sha256"]):
                raise ContractError("rollback target is not the original approved production artifact")
            verify_preview(args.public, candidate, deployment["url"], int(time.time()))
            authorization()
            progress.phase = "rollback"
            client.request(client.prefix + "/deployments/" + args.deployment_id + "/rollback", method="POST")
        else:
            manifest = client.upload_assets(args.public, candidate)
            branch = production_branch if args.operation == "promote" else "candidate-" + candidate["candidate_bundle_sha256"][:16]
            if args.operation == "preview" and branch == production_branch:
                raise ContractError("preview branch would select production")
            if args.operation == "promote":
                authorization()  # Expiry/rights/approval can change while assets upload.
            deployment = client.create(args.public, candidate, manifest, branch, args.head)
        progress.phase = "deployment-identity"
        expected_environment = "preview" if args.operation == "preview" else "production"
        if deployment.get("environment") != expected_environment:
            raise ContractError("Pages created an unexpected deployment environment")
        progress.phase = "served-preview" if expected_environment == "preview" else "served-production"
        identity = verify_preview(args.public, candidate, deployment["url"], int(time.time()))
        alias = None
        if expected_environment == "production":
            alias = verify_preview(args.public, candidate, f"https://{client.project}.pages.dev", int(time.time()), production_alias=True)
        progress.phase = "report"
        report = {"format_version": 1, "operation": args.operation, "status": "verified", "deployment_id": deployment["id"],
            "url": deployment["url"], "environment": expected_environment, "head_sha": args.head,
            "candidate_bundle_sha256": candidate["candidate_bundle_sha256"], "release_id": candidate["release_id"],
            "identity": identity, "production_alias_identity": alias}
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"PASS: exact Pages {args.operation} and served-file verification")
        return 0
    except (ContractError, OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        classification = "io" if isinstance(error, OSError) else "contract"
        if isinstance(error, PagesRequestFailure):
            classification = error.classification
        print(failure_marker(progress.phase, classification), file=sys.stderr, flush=True)
        # Preserve a source-free failed-attempt identity for bounded recovery.
        # Failure before a known deployment must not trigger an arbitrary restore.
        try:
            if not args.report.resolve().is_relative_to(args.public.resolve()):
                args.report.parent.mkdir(parents=True, exist_ok=True)
                args.report.write_text(json.dumps({"format_version": 1, "operation": args.operation,
                    "status": "failed", "deployment_id": _failure_identity(getattr(client, "created_deployment_id", None), DEPLOYMENT_ID),
                    "candidate_bundle_sha256": _failure_identity(candidate.get("candidate_bundle_sha256") if candidate else None, r"[0-9a-f]{64}"),
                    "head_sha": _failure_identity(args.head, r"[0-9a-f]{40}")}, indent=2) + "\n", encoding="utf-8")
        except (OSError, ValueError):
            # A failure to record recovery evidence must never cause raw path
            # diagnostics or allow a deployment to be marked verified.
            pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
