"""Assemble and revalidate source-free trusted-CI evidence for exact promotion.

This command neither creates approval nor deploys. Every mandatory raw gate is
checked before the canonical packet can exist; approved promotion rechecks it,
the live immutable preview, the sealed private source store and the frozen tree.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tempfile
import time
import zipfile

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.release_contract.acceptance import browser_gates, build_gates, require_all
from tools.release_contract.contracts import (ContractError, canonical_bytes, parse_canonical,
    rollback_eligible, sha256, verify_approval)
from tools.release_contract.prepare_static import inspect_binary, known_private_values, scan_frontend, verify_atlas
from tools.release_contract.production import ROOT, _keys, _hash, qualify_public, read_private
from tools.hosted.candidate import check_candidate, check_preview_origin, verify_preview

REPOSITORY = "VanSail-Opensource/vansail-ip-atlas"
CI_KINDS = {
    "candidate": (".github/workflows/production-candidate.yml", "production-candidate-evidence",
                  {"static-candidate.json", "production-build.json"}),
    "preview": (".github/workflows/production-preview.yml", "production-preview-evidence",
                {"preview-identity.json", "production-browser.json", "pages-deployment.json"}),
}


def json_object(data: bytes) -> dict:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ContractError("duplicate evidence JSON key")
            result[key] = value
        return result
    result = json.loads(data.decode("utf-8", errors="strict"), object_pairs_hook=unique,
                        parse_constant=lambda _: (_ for _ in ()).throw(ContractError("nonfinite evidence JSON")))
    if type(result) is not dict:
        raise ContractError("evidence report must be an object")
    return result


class TrustedCI:
    """Read only GitHub CLI requests; tokens remain managed by gh, never logged."""
    def _get(self, route: str) -> bytes:
        if not re.fullmatch(r"(?:actions/(?:runs/[1-9][0-9]*(?:/artifacts|/jobs)?|artifacts/[1-9][0-9]*(?:/zip)?)|environments/atlas-production|branches/main)", route):
            raise ContractError("unsupported trusted evidence route")
        with tempfile.TemporaryFile() as output:
            try:
                result = subprocess.run(["gh", "api", f"repos/{REPOSITORY}/{route}"],
                    stdout=output, stderr=subprocess.DEVNULL, timeout=90, check=False)
            except (OSError, subprocess.TimeoutExpired) as error:
                raise ContractError("trusted GitHub evidence unavailable") from error
            if result.returncode:
                raise ContractError("trusted GitHub evidence request failed")
            if output.tell() > 64 * 1024 * 1024:
                raise ContractError("source-free evidence archive exceeds bound")
            output.seek(0)
            return output.read()

    def run(self, run_id: int, head: str, workflow: str) -> dict:
        run = json_object(self._get(f"actions/runs/{run_id}"))
        if (run.get("status") != "completed" or run.get("conclusion") != "success"
                or run.get("head_sha") != head or run.get("head_branch") != "main"
                or run.get("event") not in ("push", "workflow_dispatch", "schedule", "workflow_run") or run.get("path") != workflow
                or run.get("head_repository", {}).get("full_name") != REPOSITORY):
            raise ContractError("evidence must come from successful exact-head trusted main CI")
        return run

    def protected_production_environment(self) -> None:
        environment = json_object(self._get("environments/atlas-production"))
        rules = environment.get("protection_rules", [])
        if not isinstance(rules, list):
            raise ContractError("production environment protection is unavailable")
        policy = environment.get("deployment_branch_policy")
        if (not isinstance(policy, dict) or policy.get("protected_branches") is not True
                or json_object(self._get("branches/main")).get("protected") is not True):
            raise ContractError("production requires a main-only environment and protected main branch")

    def current_head(self) -> str:
        return json_object(self._get("branches/main")).get("commit", {}).get("sha", "")

    def reports(self, kind: str, run_id: int, artifact_id: int, digest: str, head: str) -> dict[str, bytes]:
        workflow, name, required = CI_KINDS[kind]
        self.run(run_id, head, workflow)
        artifact = json_object(self._get(f"actions/artifacts/{artifact_id}"))
        if (artifact.get("name") != name or artifact.get("expired") is not False
                or artifact.get("workflow_run", {}).get("id") != run_id
                or artifact.get("workflow_run", {}).get("head_sha") != head
                or artifact.get("digest") != "sha256:" + digest
                or type(artifact.get("size_in_bytes")) is not int or not 0 < artifact["size_in_bytes"] <= 64 * 1024 * 1024):
            raise ContractError("evidence artifact identity differs from trusted CI")
        data = self._get(f"actions/artifacts/{artifact_id}/zip")
        if len(data) != artifact["size_in_bytes"] or sha256(data) != digest:
            raise ContractError("evidence archive SHA-256 differs from GitHub")
        return extract_reports(data, required)


def extract_reports(data: bytes, required: set[str]) -> dict[str, bytes]:
    """Read fixed source-free reports in memory; no extraction/traversal/symlinks."""
    result = {}
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        infos = archive.infolist()
        if len(infos) != len(required) or sum(info.file_size for info in infos) > 64 * 1024 * 1024:
            raise ContractError("unexpected evidence artifact population")
        for info in infos:
            path = PurePosixPath(info.filename)
            mode = info.external_attr >> 16
            if (info.filename not in required or info.filename in result or path.name != info.filename
                    or info.is_dir() or info.flag_bits & 1 or stat.S_IFMT(mode) not in (0, stat.S_IFREG)
                    or mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX)
                    or not 0 < info.file_size <= 48 * 1024 * 1024):
                raise ContractError("unsafe or non-source-free evidence ZIP member")
            with archive.open(info) as stream:
                contents = stream.read(48 * 1024 * 1024 + 1)
            if len(contents) != info.file_size:
                raise ContractError("evidence ZIP member length differs")
            result[info.filename] = contents
    return result


def _completed_before_packet(run: dict, assembled_at: int) -> None:
    try:
        value = run["updated_at"]
        if not isinstance(value, str) or not value.endswith("Z"):
            raise ValueError("explicit UTC required")
        finished = int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp())
    except (ValueError, KeyError, TypeError):
        raise ContractError("trusted CI completion clock unavailable") from None
    if finished > assembled_at:
        raise ContractError("acceptance packet must follow all completed hosted evidence")


def acceptance(public: Path, receipt_paths: list[Path], packet: dict, now: int, *, ci=None,
               verify_live=True) -> dict:
    packet = _keys(packet, {"format_version", "scope", "repository", "head_sha", "release_id",
        "candidate_bundle_sha256", "qualification_receipt_sha256", "preview_url", "preview_deployment_id",
        "assembled_at", "integration_run_id", "artifacts"}, "acceptance packet")
    if (type(packet["format_version"]) is not int or packet["format_version"] != 1
            or packet["scope"] != "production-acceptance-v1" or packet["repository"] != REPOSITORY
            or not re.fullmatch(r"[0-9a-f]{40}", str(packet["head_sha"]))
            or type(packet["assembled_at"]) is not int or not 0 <= packet["assembled_at"] <= now
            or not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", str(packet["preview_deployment_id"]))):
        raise ContractError("invalid production acceptance identity")
    for key in ("release_id", "candidate_bundle_sha256", "qualification_receipt_sha256"):
        _hash(packet[key])
    check_preview_origin(packet["preview_url"])
    if packet["preview_url"].split("//")[1].split(".")[0] != packet["preview_deployment_id"].split("-")[0]:
        raise ContractError("preview deployment UUID and immutable host differ")
    ci = ci or TrustedCI()
    run_id = packet["integration_run_id"]
    if type(run_id) is not int or run_id <= 0:
        raise ContractError("invalid integration run")
    _completed_before_packet(ci.run(run_id, packet["head_sha"], ".github/workflows/p0-contracts.yml"), packet["assembled_at"])
    artifacts = packet["artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) != 2:
        raise ContractError("candidate and preview trusted artifacts are required")
    reports, seen = {}, set()
    for value in artifacts:
        value = _keys(value, {"kind", "run_id", "artifact_id", "artifact_sha256"}, "trusted artifact")
        kind = value["kind"]
        if (kind not in CI_KINDS or kind in seen or type(value["run_id"]) is not int or value["run_id"] <= 0
                or type(value["artifact_id"]) is not int or value["artifact_id"] <= 0):
            raise ContractError("invalid trusted artifact population")
        seen.add(kind)
        _hash(value["artifact_sha256"])
        _completed_before_packet(ci.run(value["run_id"], packet["head_sha"], CI_KINDS[kind][0]), packet["assembled_at"])
        reports.update(ci.reports(kind, value["run_id"], value["artifact_id"], value["artifact_sha256"], packet["head_sha"]))
    parsed = {name: json_object(data) for name, data in reports.items()}
    candidate = parsed["static-candidate.json"]
    if candidate.get("mode") != "production" or candidate.get("qualification_receipt_sha256") != packet["qualification_receipt_sha256"]:
        raise ContractError("candidate was not packaged from the qualified inclusion set")
    if parsed["production-build.json"].get("normalized_state_sha256") != candidate.get("normalized_state_sha256") or not candidate.get("normalized_state_sha256"):
        raise ContractError("build scenarios do not bind the candidate's exact normalized corpus")
    check_candidate(public, candidate, now)
    for name in ("static-candidate.json", "production-build.json", "preview-identity.json", "production-browser.json"):
        report = parsed[name]
        if (report.get("release_id") != packet["release_id"]
                or report.get("candidate_bundle_sha256") != packet["candidate_bundle_sha256"]):
            raise ContractError("trusted report does not bind the exact frozen candidate")
    for name in ("preview-identity.json", "production-browser.json"):
        if parsed[name].get("url") != packet["preview_url"]:
            raise ContractError("trusted preview reports refer to another deployment")
    deployment = parsed["pages-deployment.json"]
    if (deployment.get("status") != "verified" or deployment.get("operation") != "preview"
            or deployment.get("environment") != "preview" or deployment.get("head_sha") != packet["head_sha"]
            or deployment.get("deployment_id") != packet["preview_deployment_id"]
            or deployment.get("url") != packet["preview_url"] or deployment.get("release_id") != packet["release_id"]
            or deployment.get("candidate_bundle_sha256") != packet["candidate_bundle_sha256"]):
        raise ContractError("trusted preview deployment metadata differs from the accepted artifact")
    preview = parsed["preview-identity.json"]
    if (preview.get("status") != "passed" or preview.get("scope") != "hosted-production-preview-identity"
            or preview.get("verified_files") != candidate["files"] - 2
            or preview.get("control_files_verified_through_effective_headers_and_redirect") is not True):
        raise ContractError("preview full inventory/control verification incomplete")
    gates = {**browser_gates(parsed["production-browser.json"]), **build_gates(parsed["production-build.json"])}
    require_all(gates)
    metadata = verify_atlas(public / "_atlas", now, production=True, credits=True)
    qualify_public(public, candidate, receipt_paths, now)
    private_values = known_private_values()
    if inspect_binary(public / "_atlas", private_values) != metadata["object_count"]:
        raise ContractError("production decoded scanner did not inspect every VIA3 object")
    scan_frontend(public, private_values)
    if verify_live:
        verify_preview(public, candidate, packet["preview_url"], now)
    return {"format_version": 1, "scope": "production-promotion-authorization-v1", "status": "passed",
        "production_eligible": False,
        "pages_release": {"capability": "pages_release", "required": True, "status": "awaiting_policy",
                          "evidence_sha256": sha256(canonical_bytes(packet))},
        "candidate_bundle_sha256": packet["candidate_bundle_sha256"], "release_id": packet["release_id"],
        "evidence_sha256": sha256(canonical_bytes(packet)), "head_sha": packet["head_sha"],
        "preview_deployment_id": packet["preview_deployment_id"], "valid_until": metadata["valid_until"],
        "gates": gates, "report_sha256": {name: sha256(data) for name, data in sorted(reports.items())}}


def approve(public: Path, receipt_paths: list[Path], evidence: bytes, approval: dict, now: int, **kwargs) -> dict:
    packet = parse_canonical(evidence)
    result = acceptance(public, receipt_paths, packet, now, **kwargs)
    from tools.atlas_contracts.config import validate_schema
    validate_schema("release-approval", approval)
    approver = approval.get("approver")
    if not isinstance(approver, str) or approver.strip() != approver or not approver or not approver.isprintable():
        raise ContractError("a named exact-artifact approver is required")
    try:
        stamp = approval["approved_at"]
        if not isinstance(stamp, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", stamp):
            raise ValueError("UTC approval required")
        approved_at = int(datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp())
    except (ValueError, TypeError, KeyError) as error:
        raise ContractError("explicit UTC exact-artifact approval is required") from error
    if not packet["assembled_at"] <= approved_at <= now:
        raise ContractError("approval must follow the accepted evidence and precede promotion")
    manifest = (public / "_atlas/releases" / packet["release_id"] / "manifest.json").read_bytes()
    verify_approval(approval, (ROOT / "configs/sources.yaml").read_bytes(), (ROOT / "SOURCES_AUDIT.md").read_bytes(),
                    manifest, packet["candidate_bundle_sha256"], evidence)
    result["production_eligible"] = True
    result["pages_release"]["status"] = "qualified"
    return result


def automatic(public: Path, receipt_paths: list[Path], evidence: bytes, now: int, *, ci=None,
              rollback=False, **kwargs) -> dict:
    """The reviewed policy authorizes exact passing bytes, never source admission."""
    policy_bytes = (ROOT / 'configs/production-policy.json').read_bytes().rstrip(b'\n')
    policy = parse_canonical(policy_bytes)
    expected = {'automatic_promotion': True, 'contract_revision': 1,
        'maximum_checkpoint_age_seconds': 604800, 'maximum_rollback_age_seconds': 172800,
        'repository': REPOSITORY, 'require_all_measured_gates': True,
        'require_current_source_qualification': True, 'require_exact_head_integration': True,
        'require_protected_main': True, 'scope': 'release-scope-v5'}
    if policy != expected:
        raise ContractError('unrecognized automatic production policy')
    ci = ci or TrustedCI()
    ci.protected_production_environment()
    packet = parse_canonical(evidence)
    if not rollback and ci.current_head() != packet['head_sha']:
        raise ContractError('automatic candidate no longer matches protected main')
    result = acceptance(public, receipt_paths, packet, now, ci=ci, **kwargs)
    result.update(production_eligible=True, authorization='reviewed-automatic-policy-v1',
                  policy_sha256=sha256(policy_bytes))
    result['pages_release']['status'] = 'qualified'
    return result


def assemble(public: Path, receipt_paths: list[Path], head: str, integration: int, candidate_run: int,
             preview_run: int, now: int, *, ci=None) -> tuple[bytes, dict]:
    """Create reviewable canonical evidence only after the underlying gates pass."""
    ci = ci or TrustedCI()
    artifacts, reports = [], {}
    for kind, run_id in (("candidate", candidate_run), ("preview", preview_run)):
        if type(run_id) is not int or run_id <= 0:
            raise ContractError("invalid acceptance run identity")
        ci.run(run_id, head, CI_KINDS[kind][0])
        listing = json_object(ci._get(f"actions/runs/{run_id}/artifacts"))
        matches = [entry for entry in listing.get("artifacts", []) if entry.get("name") == CI_KINDS[kind][1]
                   and entry.get("expired") is False]
        if len(matches) != 1:
            raise ContractError("one unexpired trusted evidence artifact is required per run")
        entry = matches[0]
        digest = entry.get("digest", "")
        if not isinstance(digest, str) or not digest.startswith("sha256:"):
            raise ContractError("GitHub evidence artifact digest unavailable")
        digest = _hash(digest.removeprefix("sha256:"))
        artifacts.append({"kind": kind, "run_id": run_id, "artifact_id": entry["id"], "artifact_sha256": digest})
        reports.update(ci.reports(kind, run_id, entry["id"], digest, head))
    candidate = json_object(reports["static-candidate.json"])
    preview = json_object(reports["pages-deployment.json"])
    packet = {"format_version": 1, "scope": "production-acceptance-v1", "repository": REPOSITORY,
        "head_sha": head, "release_id": candidate["release_id"], "candidate_bundle_sha256": candidate["candidate_bundle_sha256"],
        "qualification_receipt_sha256": candidate["qualification_receipt_sha256"], "preview_url": preview["url"],
        "preview_deployment_id": preview["deployment_id"], "assembled_at": now, "integration_run_id": integration,
        "artifacts": artifacts}
    result = acceptance(public, receipt_paths, packet, now, ci=ci)
    return canonical_bytes(packet), result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public", type=Path, required=True)
    parser.add_argument("--qualification-receipt", type=Path, action="append", required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--approval", type=Path)
    parser.add_argument("--automatic", action="store_true")
    parser.add_argument("--assemble", action="store_true", help="write a canonical packet only after raw gate verification")
    parser.add_argument("--head")
    parser.add_argument("--integration-run-id", type=int)
    parser.add_argument("--candidate-run-id", type=int)
    parser.add_argument("--preview-run-id", type=int)
    parser.add_argument("--report", type=Path, default=Path("reports/production-authorization.json"))
    args = parser.parse_args()
    try:
        if args.report.resolve().is_relative_to(args.public.resolve()):
            raise ContractError("promotion reports must remain outside the frozen tree")
        if args.assemble:
            if args.approval or args.evidence.resolve().is_relative_to(args.public.resolve()):
                raise ContractError("evidence assembly is separate from approval and outside the frozen tree")
            evidence, result = assemble(args.public, args.qualification_receipt, args.head, args.integration_run_id,
                                       args.candidate_run_id, args.preview_run_id, int(time.time()))
            args.evidence.parent.mkdir(parents=True, exist_ok=True)
            with args.evidence.open("xb") as output:
                output.write(evidence)
            result["scope"] = "production-evidence-verified-awaiting-policy"
        elif args.automatic:
            if args.approval:
                raise ContractError('automatic policy cannot be combined with a manual approval')
            result = automatic(args.public, args.qualification_receipt, read_private(args.evidence), int(time.time()))
        elif args.approval:
            evidence = read_private(args.evidence)
            from tools.atlas_contracts.config import load_yaml
            result = approve(args.public, args.qualification_receipt, evidence, load_yaml(args.approval), int(time.time()))
        else:
            evidence = read_private(args.evidence)
            result = acceptance(args.public, args.qualification_receipt, parse_canonical(evidence), int(time.time()))
            result["scope"] = "production-evidence-verified-awaiting-policy"
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_bytes(canonical_bytes(result))
        print("PASS: exact production evidence" + (" and automatic policy" if args.automatic else " and explicit legacy approval" if args.approval else "; policy authorization remains required"))
        return 0
    except (ContractError, OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile) as error:
        # Contract errors are deliberately source-free; never include downloaded bytes.
        print(f"FAIL: production promotion: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
