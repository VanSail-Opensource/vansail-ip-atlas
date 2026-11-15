"""Bounded Pages Direct Upload of a frozen candidate; never rebuild or approve.

Preview uploads need qualified production input receipts. Production additionally
requires the complete trusted acceptance packet and explicit exact-artifact
approval, rechecked immediately before creating the deployment. Credentials and
ephemeral asset JWTs are never printed, serialized or written to disk.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import mimetypes
import os
from pathlib import Path
import re
import sys
import time
import urllib.error
import urllib.request
import uuid

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.hosted.candidate import check_candidate, verify_preview
from tools.release_contract.contracts import ContractError, parse_canonical, rollback_eligible, sha256, tree_inventory
from tools.release_contract.production import qualify_public, read_private
from tools.release_contract.prepare_static import inspect_binary, known_private_values, scan_frontend, verify_atlas
from tools.release_contract.promotion import approve, json_object

API = "https://api.cloudflare.com/client/v4"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


class Pages:
    def __init__(self, account: str, project: str, token: str):
        if (not re.fullmatch(r"[0-9a-f]{32}", account)
                or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,56}[a-z0-9])?", project)
                or not isinstance(token, str) or not token.isascii() or not 20 <= len(token) <= 4096
                or any(ord(ch) <= 32 or ord(ch) == 127 for ch in token)):
            raise ContractError("valid scoped Pages account/project credentials required")
        self.project = project
        self.prefix = f"/accounts/{account}/pages/projects/{project}"
        self._token = token
        self._opener = urllib.request.build_opener(NoRedirect)

    def request(self, path: str, *, method="GET", value=None, body=None, content_type="application/json", asset_token=None):
        if path != self.prefix and not path.startswith(self.prefix + "/") and path not in (
                "/pages/assets/check-missing", "/pages/assets/upload", "/pages/assets/upsert-hashes"):
            raise ContractError("unsupported Pages API route")
        if any(ch in path for ch in "?#\\") or ".." in path.split("/"):
            raise ContractError("unsafe Pages API route")
        payload = json.dumps(value, separators=(",", ":")).encode() if value is not None else body
        token = asset_token or self._token
        request = urllib.request.Request(API + path, data=payload, method=method,
            headers={"Authorization": "Bearer " + token, "Content-Type": content_type,
                     "User-Agent": "VanSail-IP-Atlas-Release/1.0"})
        try:
            with self._opener.open(request, timeout=60) as response:
                data = response.read(2 * 1024 * 1024 + 1)
        except urllib.error.HTTPError as error:
            # API bodies/locations can contain secret-bearing context. Never echo.
            raise ContractError(f"Pages API request failed (HTTP {error.code})") from None
        except OSError:
            raise ContractError("Pages API request unavailable") from None
        if len(data) > 2 * 1024 * 1024:
            raise ContractError("Pages API response exceeds bound")
        result = json_object(data)
        if result.get("success") is not True:
            raise ContractError("Pages API rejected the operation")
        return result.get("result")

    def upload_assets(self, public: Path, candidate: dict) -> dict[str, str]:
        verified = check_candidate(public, candidate, int(time.time()))
        result = self.request(self.prefix + "/upload-token")
        if not isinstance(result, dict) or not isinstance(result.get("jwt"), str):
            raise ContractError("ephemeral Pages asset credential unavailable")
        jwt = result["jwt"]
        if not jwt.isascii() or not 20 <= len(jwt) <= 8192 or any(ord(ch) <= 32 or ord(ch) == 127 for ch in jwt):
            raise ContractError("invalid ephemeral Pages asset credential")
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
        missing = []
        for index in range(0, len(keys), 1000):
            requested = keys[index:index + 1000]
            absent = self.request("/pages/assets/check-missing", method="POST", value={"hashes": requested}, asset_token=jwt)
            if (not isinstance(absent, list) or len(absent) != len(set(absent))
                    or any(key not in requested for key in absent)):
                raise ContractError("invalid Pages missing-asset response")
            missing.extend(absent)
        batch, batch_size = [], 0
        def flush():
            nonlocal batch, batch_size
            if batch:
                self.request("/pages/assets/upload", method="POST", value=batch, asset_token=jwt)
                batch, batch_size = [], 0
        for key in missing:
            relative, size, digest = assets[key]
            data = (public / relative).read_bytes()
            if len(data) != size or sha256(data) != digest:
                raise ContractError("frozen asset changed before upload")
            content = base64.b64encode(data).decode("ascii")
            if batch and batch_size + len(content) > 34 * 1024 * 1024:
                flush()
            mime = "application/javascript" if relative.endswith((".js", ".mjs")) else mimetypes.guess_type(relative)[0] or "application/octet-stream"
            batch.append({"key": key, "base64": True, "value": content, "metadata": {"contentType": mime}})
            batch_size += len(content)
        flush()
        for index in range(0, len(keys), 1000):
            self.request("/pages/assets/upsert-hashes", method="POST", value={"hashes": keys[index:index + 1000]}, asset_token=jwt)
        check_candidate(public, candidate, int(time.time()))
        return manifest

    def create(self, public: Path, candidate: dict, manifest: dict, branch: str, head: str) -> dict:
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
        if not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", str(deployment_id)):
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
    parser.add_argument("--deployment-id")
    parser.add_argument("--account", required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--report", type=Path, default=Path("reports/pages-deployment.json"))
    args = parser.parse_args()
    client, candidate = None, None
    try:
        if not re.fullmatch(r"[0-9a-f]{40}", args.head) or args.report.resolve().is_relative_to(args.public.resolve()):
            raise ContractError("invalid deployment revision or report location")
        candidate = json_object(read_private(args.candidate_report))
        check_candidate(args.public, candidate, int(time.time()))
        if candidate["mode"] != "production":
            raise ContractError("production workflow cannot upload synthetic data")
        qualify_public(args.public, candidate, args.qualification_receipt, int(time.time()))
        atlas = verify_atlas(args.public / "_atlas", int(time.time()), production=True, credits=True)
        private_values = known_private_values()
        if inspect_binary(args.public / "_atlas", private_values) != atlas["object_count"]:
            raise ContractError("Pages candidate binary scanner did not inspect all objects")
        scan_frontend(args.public, private_values)
        def authorization():
            if not args.evidence or not args.approval:
                raise ContractError("production promotion requires exact evidence and explicit approval")
            from tools.atlas_contracts.config import load_yaml
            evidence = read_private(args.evidence)
            if parse_canonical(evidence)["head_sha"] != args.head:
                raise ContractError("deployment revision differs from approved evidence")
            return approve(args.public, args.qualification_receipt, evidence, load_yaml(args.approval), int(time.time()))
        if args.operation != "preview":
            authorization()
        client = Pages(args.account, args.project, os.environ.get("CLOUDFLARE_API_TOKEN", ""))
        project = client.request(client.prefix)
        production_branch = project.get("production_branch")
        if not isinstance(production_branch, str) or not production_branch:
            raise ContractError("Pages production branch unavailable")
        if args.operation == "rollback":
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
            client.request(client.prefix + "/deployments/" + args.deployment_id + "/rollback", method="POST")
        else:
            manifest = client.upload_assets(args.public, candidate)
            branch = production_branch if args.operation == "promote" else "candidate-" + candidate["candidate_bundle_sha256"][:16]
            if args.operation == "preview" and branch == production_branch:
                raise ContractError("preview branch would select production")
            if args.operation == "promote":
                authorization()  # Expiry/rights/approval can change while assets upload.
            deployment = client.create(args.public, candidate, manifest, branch, args.head)
        expected_environment = "preview" if args.operation == "preview" else "production"
        if deployment.get("environment") != expected_environment:
            raise ContractError("Pages created an unexpected deployment environment")
        identity = verify_preview(args.public, candidate, deployment["url"], int(time.time()))
        alias = None
        if expected_environment == "production":
            alias = verify_preview(args.public, candidate, f"https://{client.project}.pages.dev", int(time.time()), production_alias=True)
        report = {"format_version": 1, "operation": args.operation, "status": "verified", "deployment_id": deployment["id"],
            "url": deployment["url"], "environment": expected_environment, "head_sha": args.head,
            "candidate_bundle_sha256": candidate["candidate_bundle_sha256"], "release_id": candidate["release_id"],
            "identity": identity, "production_alias_identity": alias}
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"PASS: exact Pages {args.operation} and served-file verification")
        return 0
    except (ContractError, OSError, ValueError, KeyError, TypeError) as error:
        # Preserve a source-free failed-attempt identity for bounded recovery.
        # Failure before a known deployment must not trigger an arbitrary restore.
        if not args.report.resolve().is_relative_to(args.public.resolve()):
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps({"format_version": 1, "operation": args.operation,
                "status": "failed", "deployment_id": getattr(client, "created_deployment_id", None),
                "candidate_bundle_sha256": candidate.get("candidate_bundle_sha256") if candidate else None,
                "head_sha": args.head}, indent=2) + "\n", encoding="utf-8")
        print(f"FAIL: Pages release: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
