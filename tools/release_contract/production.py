"""Private production qualification and exact-artifact acceptance contracts.

A receipt is not an approval. The Go verifier reopens the eligible source store;
hashes and caller-supplied success flags cannot substitute for that verification.
Only the returned aggregate digests may be copied into source-free CI evidence.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Callable

from .contracts import ContractError, HASH, canonical_bytes, parse_canonical, sha256

ROOT = Path(__file__).resolve().parents[2]
MAX_RECEIPT_BYTES = 2 * 1024 * 1024
SOURCE_CAPABILITIES = frozenset({"country", "region_city", "coordinates", "asn_prefix", "usage",
    "risk_reasons", "class_c", "rpki", "bgp_origins_paths", "relationships", "tier1"})


def _fail(message: str) -> None:
    raise ContractError(message)


def _keys(value: object, keys: set[str], label: str) -> dict:
    if type(value) is not dict or set(value) != keys:
        _fail(f"{label}: unexpected or missing fields")
    return value


def _hash(value: object) -> str:
    if not isinstance(value, str) or HASH.fullmatch(value) is None:
        _fail("production binding requires a lowercase SHA-256")
    return value


def _clock(value: object) -> int:
    if type(value) is not int or not 0 <= value <= 2**53 - 1:
        _fail("invalid production UTC clock")
    return value


def read_private(path: Path, maximum: int = MAX_RECEIPT_BYTES) -> bytes:
    """Bounded regular-file reads; reject links/junctions in every component."""
    absolute = path.absolute()
    for part in [*reversed(absolute.parents), absolute]:
        info = part.lstat()
        if (stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)):
            _fail("private evidence cannot traverse links")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(absolute, flags), "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= maximum:
            _fail("private evidence must be a bounded regular file")
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        _fail("private evidence exceeds its bound")
    return data


@dataclass(frozen=True)
class IncludedSource:
    source_id: str
    payload_sha256: str
    proof_sha256: str
    published_at: int
    expires_at: int
    parser: str
    schema: str
    parser_version: int
    evidence_family: str
    rights_sha256: str
    attribution_sha256: str | None


@dataclass(frozen=True)
class Qualification:
    release_id: str
    manifest_sha256: str
    evaluated_at: int
    valid_until: int
    receipt_sha256: str
    normalized_state_sha256: str
    sources: tuple[IncludedSource, ...]
    credits: tuple[dict, ...]


def _verify_store(workspace: Path, receipt: Path, atlas: Path, now: int) -> None:
    command = ["go", "run", "./cmd/atlas", "verify-production", "-workspace", str(workspace),
               "-receipt", str(receipt.resolve()), "-atlas", str(atlas.resolve()), "-clock", str(now)]
    try:
        result = subprocess.run(command, cwd=workspace, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=600, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ContractError("production source-store revalidation unavailable") from error
    if result.returncode:
        _fail("production source-store revalidation failed")


def qualify(receipt_path: Path, atlas: Path, now: int, *, workspace: Path = ROOT,
            verifier: Callable[[Path, Path, Path, int], None] = _verify_store) -> Qualification:
    """Validate closed receipt, exact catalog/credits, manifest and CURRENT store.

    `verifier` is injectable for focused fixtures; the CLI never exposes an override.
    Production invokes the Go revalidator even when every receipt digest matches.
    """
    from tools.atlas_contracts.config import load_yaml
    from .dataset_credits import build_credit_document

    _clock(now)
    data = read_private(receipt_path)
    receipt = _keys(parse_canonical(data), {"schema_version", "release_scope", "mode", "evaluated_at",
        "valid_until", "release_id", "release_manifest_sha256", "source_catalog_sha256", "rights_audit_sha256",
        "normalization_config_sha256", "implementation_sha256", "certification_sha256", "normalized_state_sha256",
        "source_capabilities_sha256", "included_sources"}, "production receipt")
    if (receipt["schema_version"] != 1 or type(receipt["schema_version"]) is not int
            or receipt["release_scope"] != "release-scope-v5" or receipt["mode"] != "production"):
        _fail("unsupported production qualification scope")
    for name, value in receipt.items():
        if name.endswith("_sha256") or name == "release_id":
            _hash(value)
    start, expiry = _clock(receipt["evaluated_at"]), _clock(receipt["valid_until"])
    if not start <= now < expiry or expiry - start > 720 * 3600:
        _fail("production receipt is expired or has an invalid evaluation interval")
    catalog_bytes = read_private(workspace / "configs/sources.yaml")
    if sha256(catalog_bytes) != receipt["source_catalog_sha256"]:
        _fail("production catalog changed since materialization")
    if sha256(read_private(workspace / "SOURCES_AUDIT.md")) != receipt["rights_audit_sha256"]:
        _fail("production rights audit changed since materialization")
    catalog = load_yaml(workspace / "configs/sources.yaml")
    by_id = {source["id"]: source for source in catalog["sources"]}
    included = receipt["included_sources"]
    if not isinstance(included, list) or not 1 <= len(included) <= 1000:
        _fail("production receipt needs a bounded nonempty inclusion set")
    sources, credits, ids = [], [], []
    for value in included:
        value = _keys(value, {"source_id", "payload_sha256", "proof_sha256", "published_at", "expires_at",
            "parser", "schema", "parser_version", "evidence_family", "rights_sha256", "attribution_sha256"}, "included source")
        sid = value["source_id"]
        if not isinstance(sid, str) or sid not in by_id:
            _fail("included source is absent from the current catalog")
        source = by_id[sid]
        if source["admission"] != "active":
            _fail("included source is not active")
        for name in ("payload_sha256", "proof_sha256", "rights_sha256"):
            _hash(value[name])
        if value["proof_sha256"] != value["payload_sha256"]:
            _fail("publication proof is not bound to the exact included payload")
        publication, source_expiry = _clock(value["published_at"]), _clock(value["expires_at"])
        if not publication <= start + 24 * 3600 or not now < source_expiry or expiry > source_expiry:
            _fail("included source publication/expiry does not bound the release")
        parser, rights = source["parser"], source["license"]
        if (value["parser"] != parser["id"] or value["schema"] != parser["schema"]
                or type(value["parser_version"]) is not int or value["parser_version"] != parser["version"]
                or value["evidence_family"] != source["evidence_family"]
                or rights["status"] != "reviewed" or rights["distribution"] != "allow"
                or type(rights["attribution_required"]) is not bool
                or value["rights_sha256"] != sha256(canonical_bytes(rights))):
            _fail("included source parser/family/rights binding changed")
        expected_credit = rights.get("attribution") if rights["attribution_required"] else None
        expected_hash = sha256(canonical_bytes(expected_credit)) if expected_credit is not None else None
        if (rights["attribution_required"] and expected_credit is None
                or value["attribution_sha256"] != expected_hash):
            _fail("included source reviewed credit binding changed")
        if expected_credit is not None:
            credits.append(expected_credit)
        ids.append(sid)
        sources.append(IncludedSource(**value))
    if ids != sorted(set(ids)):
        _fail("included sources must be unique and ordered")
    release_id = receipt["release_id"]
    manifest_bytes = read_private(atlas / "releases" / release_id / "manifest.json", 4 * 1024 * 1024)
    manifest = parse_canonical(manifest_bytes)
    if (sha256(manifest_bytes) != receipt["release_manifest_sha256"] or manifest["mode"] != "production"
            or manifest["release_id"] != release_id or manifest["valid_from"] != start
            or manifest["valid_until"] != expiry):
        _fail("qualification does not bind the compiled production manifest")
    # This validates text/URL limits and exact deduplication before any public write.
    document = parse_canonical(build_credit_document(release_id, "production", credits))
    verifier(workspace, receipt_path, atlas, now)
    return Qualification(release_id, receipt["release_manifest_sha256"], start, expiry,
                         sha256(data), receipt["normalized_state_sha256"], tuple(sources), tuple(document["entries"]))


def qualify_public(public: Path, candidate: dict, receipt_paths: list[Path], now: int) -> dict[str, Qualification]:
    """Revalidate every retained inclusion set and exact reviewed public notices."""
    from .dataset_credits import build_credit_document, validate_credit_tree
    results = {}
    for path in receipt_paths:
        result = qualify(path, public / "_atlas", now)
        if result.release_id in results:
            _fail("duplicate retained qualification")
        results[result.release_id] = result
    modes = {path.parent.name: "production" for path in (public / "_atlas/releases").glob("*/manifest.json")}
    if (set(results) != set(modes) or candidate["release_id"] not in results
            or results[candidate["release_id"]].receipt_sha256 != candidate.get("qualification_receipt_sha256")
            or results[candidate["release_id"]].normalized_state_sha256 != candidate.get("normalized_state_sha256")):
        _fail("every retained release requires its exact current source-store qualification")
    validate_credit_tree(public, candidate["release_id"], modes)
    index = parse_canonical((public / "dataset-credits.json").read_bytes())
    for entry in index["releases"]:
        result = results[entry["release_id"]]
        expected = build_credit_document(result.release_id, "production", list(result.credits))
        if (public / entry["credits_path"].lstrip("/")).read_bytes() != expected:
            _fail("global credits differ from included reviewed source obligations")
    return results
