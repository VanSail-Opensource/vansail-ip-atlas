"""Source-free identity, freshness, inventory and disclosure contract checks.

This module checks the P0 contract independently from the future VIA3 readers.
It deliberately refuses to certify compressed public records without a reader.
"""

from __future__ import annotations

import hashlib
import base64
import json
import ipaddress
from pathlib import Path, PurePosixPath
import re
import unicodedata
from urllib.parse import unquote

MAX_FILES = 18_500
MAX_ASSET_BYTES = 24 * 1024 * 1024
MAX_TREE_BYTES = 3072 * 1024 * 1024
MAX_SOURCE_AGE_SECONDS = 720 * 3600
MAX_SUBSCRIPTION_AGE_SECONDS = 168 * 3600
ROLLBACK_MAX_AGE_SECONDS = 48 * 3600
HASH = re.compile(r"[0-9a-f]{64}\Z")
PARTITION = re.compile(r"(?:all|[46]:[0-9a-f]{32}/(?:[0-9]|[1-9][0-9]|1[01][0-9]|12[0-8])|asn:[0-9]+:[0-9]+)\Z")
DENIED_KEYS = frozenset({
    "timezone", "postal", "continent", "collector", "latency", "protocol",
    "port", "hostname", "domain", "source_id", "source_name", "source_url",
    "credentials", "credential", "password", "subscription_uri", "provenance",
    "source_count", "per_source_evidence", "raw_path",
    "evidence_family", "correlation_group", "source_group", "publication_proof",
    "published_at", "raw_evidence", "source_records", "collector_id",
    "evidencefamily", "correlationgroup", "sourcegroup", "publicationproof",
    "publishedat", "sourceid", "sourcename", "sourceurl", "collectorid",
})
BAD_STRING = re.compile(
    r"(?:[a-z][a-z0-9+.-]*://|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+|"
    r"\b(?:[a-z0-9-]+\.)+[a-z][a-z0-9-]{1,62}\b|"
    r"\b(?:vless|vmess|trojan|ssr?|hy2?|hysteria2?|tuic|anytls):)",
    re.IGNORECASE,
)


class ContractError(ValueError):
    """A release cannot satisfy its frozen contract."""


def _fail(message: str) -> None:
    raise ContractError(message)


def _exact_keys(value: object, keys: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != keys:
        _fail(f"{label}: unexpected or missing fields")
    return value


def _integer(value: object, minimum: int, maximum: int, label: str) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _fail(f"{label}: integer outside bounds")
    return value


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_bytes(value: object) -> bytes:
    """Canonical JSON v1: UTF-8/NFC, sorted ASCII keys, integer numbers, no LF."""
    def check(item: object) -> None:
        if item is None or type(item) in (bool, int):
            if type(item) is int and abs(item) > 2**53 - 1:
                _fail("canonical JSON integer exceeds exact browser range")
            return
        if isinstance(item, str):
            if unicodedata.normalize("NFC", item) != item:
                _fail("canonical JSON strings must already be NFC")
            try:
                item.encode("utf-8", errors="strict")
            except UnicodeEncodeError:
                _fail("canonical JSON invalid Unicode")
            return
        if isinstance(item, list):
            for entry in item:
                check(entry)
            return
        if isinstance(item, dict):
            for key, entry in item.items():
                if not isinstance(key, str) or not key.isascii():
                    _fail("canonical JSON keys must be ASCII strings")
                check(entry)
            return
        _fail("canonical JSON floats and non-JSON values are forbidden")
    check(value)
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def parse_canonical(data: bytes) -> object:
    def unique(pairs: list) -> dict:
        result = {}
        for key, value in pairs:
            if key in result:
                _fail("duplicate JSON key")
            result[key] = value
        return result
    try:
        value = json.loads(data.decode("utf-8", errors="strict"), object_pairs_hook=unique)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ContractError("invalid JSON") from error
    if canonical_bytes(value) != data:
        _fail("noncanonical JSON encoding")
    return value


def aggregate_expiry(observations: list[tuple[int, int | None, bool]]) -> int:
    """Inputs: verified snapshot publication, optional item publication, subscription."""
    if not observations:
        _fail("a release needs at least one verified observation")
    expiries = []
    for snapshot, item, subscription in observations:
        _integer(snapshot, 0, 2**53 - 1, "snapshot clock")
        if type(subscription) is not bool:
            _fail("subscription marker must be boolean")
        if subscription and item is None:
            _fail("subscription item publication clock is unknown")
        if item is not None:
            _integer(item, 0, 2**53 - 1, "item clock")
        lifetime = MAX_SUBSCRIPTION_AGE_SECONDS if subscription else MAX_SOURCE_AGE_SECONDS
        expiries.append(snapshot + lifetime)
        if item is not None:
            expiries.append(item + lifetime)
    return min(expiries)


def eligible(valid_from: int, valid_until: int, now: int, *, withdrawn: bool = False) -> bool:
    for name, value in (("valid_from", valid_from), ("valid_until", valid_until), ("now", now)):
        _integer(value, 0, 2**53 - 1, name)
    return not withdrawn and valid_from <= now < valid_until


def rollback_eligible(valid_from: int, valid_until: int, now: int, *, withdrawn: bool = False) -> bool:
    return eligible(valid_from, valid_until, now, withdrawn=withdrawn) and now - valid_from < ROLLBACK_MAX_AGE_SECONDS


def validate_descriptor(descriptor: object) -> dict:
    value = _exact_keys(descriptor, {"format_version", "schema_version", "codec", "mode",
                                   "valid_from", "valid_until", "objects"}, "descriptor")
    if value["format_version"] != 3 or value["schema_version"] != 3 or value["codec"] != "zstd-1":
        _fail("unsupported release version or codec")
    if value["mode"] not in ("synthetic", "production"):
        _fail("unknown release mode")
    _integer(value["valid_from"], 0, 2**53 - 1, "valid_from")
    _integer(value["valid_until"], 1, 2**53 - 1, "valid_until")
    if not 0 < value["valid_until"] - value["valid_from"] <= MAX_SOURCE_AGE_SECONDS:
        _fail("invalid aggregate validity interval")
    objects = value["objects"]
    if not isinstance(objects, list) or not 1 <= len(objects) < MAX_FILES:
        _fail("invalid object count")
    hashes = []
    for entry in objects:
        obj = _exact_keys(entry, {"sha256", "bytes", "kind", "partition"}, "object")
        if not isinstance(obj["sha256"], str) or not HASH.fullmatch(obj["sha256"]):
            _fail("invalid object hash")
        _integer(obj["bytes"], 64, MAX_ASSET_BYTES - 1, "object bytes")
        _integer(obj["kind"], 1, 14, "shard kind")
        if not isinstance(obj["partition"], str) or not PARTITION.fullmatch(obj["partition"]):
            _fail("invalid partition descriptor")
        partition = obj["partition"]
        if partition.startswith(("4:", "6:")):
            family, network = partition.split(":", 1)
            encoded, bits = network.split("/")
            raw = bytes.fromhex(encoded)
            if family == "4":
                if any(raw[:12]) or int(bits) > 32:
                    _fail("invalid IPv4 partition encoding")
                raw = raw[12:]
            try:
                ipaddress.ip_network((ipaddress.ip_address(raw), int(bits)), strict=True)
            except ValueError:
                _fail("partition host bits or prefix length invalid")
        elif partition.startswith("asn:"):
            _, first, last = partition.split(":")
            if not 1 <= int(first) <= int(last) <= 4294967294 or str(int(first)) != first or str(int(last)) != last:
                _fail("invalid ASN partition range")
        hashes.append(obj["sha256"])
    if hashes != sorted(set(hashes)):
        _fail("objects must have unique ascending hashes")
    canonical_bytes(value)
    return value


def make_manifest(descriptor: dict) -> tuple[bytes, bytes]:
    value = validate_descriptor(descriptor)
    release_id = sha256(canonical_bytes(value))
    manifest = canonical_bytes({**value, "release_id": release_id})
    pointer = canonical_bytes({"format_version": 3, "release_id": release_id,
                               "manifest_path": f"/_atlas/releases/{release_id}/manifest.json",
                               "manifest_sha256": sha256(manifest)})
    return manifest, pointer


def verify_manifest(manifest_bytes: bytes, pointer_bytes: bytes, now: int) -> dict:
    pointer = _exact_keys(parse_canonical(pointer_bytes),
                          {"format_version", "release_id", "manifest_path", "manifest_sha256"}, "pointer")
    manifest = _exact_keys(parse_canonical(manifest_bytes),
                           {"format_version", "schema_version", "codec", "mode", "valid_from",
                            "valid_until", "objects", "release_id"}, "manifest")
    descriptor = {key: value for key, value in manifest.items() if key != "release_id"}
    validate_descriptor(descriptor)
    release_id = sha256(canonical_bytes(descriptor))
    expected_path = f"/_atlas/releases/{release_id}/manifest.json"
    if (pointer["format_version"] != 3 or pointer["release_id"] != release_id or
            manifest["release_id"] != release_id or pointer["manifest_path"] != expected_path or
            pointer["manifest_sha256"] != sha256(manifest_bytes)):
        _fail("pointer/manifest identity mismatch")
    if not eligible(manifest["valid_from"], manifest["valid_until"], now):
        _fail("release not currently eligible")
    return manifest


def validate_inventory(entries: list[tuple[str, int, str]]) -> str:
    """Digest the ENTIRE deployment tree, including control files and old generation."""
    if len(entries) >= MAX_FILES:
        _fail("Pages file ceiling reached")
    names = set()
    inventory = []
    total = 0
    for path, size, digest in entries:
        parts = PurePosixPath(path).parts
        if (not path or not path.isascii() or path.startswith("/") or "\\" in path or
                any(part in ("", ".", "..") for part in path.split("/")) or
                any(part.startswith(".") for part in parts) or "%" in path or ":" in path):
            _fail("unsafe deployment path")
        if path in names:
            _fail("duplicate deployment path")
        names.add(path)
        _integer(size, 0, MAX_ASSET_BYTES - 1, "asset bytes")
        if not isinstance(digest, str) or not HASH.fullmatch(digest):
            _fail("invalid inventory hash")
        total += size
        inventory.append({"path": path, "bytes": size, "sha256": digest})
    if total > MAX_TREE_BYTES:
        _fail("generated tree budget exceeded")
    return sha256(canonical_bytes(sorted(inventory, key=lambda entry: entry["path"].encode("ascii"))))


def tree_inventory(root: Path) -> tuple[list[tuple[str, int, str]], str]:
    if not root.is_dir() or root.is_symlink():
        _fail("deployment root must be a real directory")
    entries = []
    for path in root.rglob("*"):
        if path.is_symlink():
            _fail("deployment symlinks forbidden")
        if path.is_file():
            size = path.stat().st_size
            if size >= MAX_ASSET_BYTES:
                _fail("Pages asset ceiling reached")
            entries.append((path.relative_to(root).as_posix(), size, sha256(path.read_bytes())))
    return entries, validate_inventory(entries)


def scan_public_records(records: object, private_values: tuple[str, ...] = ()) -> None:
    """Scan DECODED data and dictionaries, never exempt map URLs in IP records."""
    if isinstance(records, dict):
        for key, value in records.items():
            if not isinstance(key, str) or key.lower() in DENIED_KEYS:
                _fail("forbidden public metadata key")
            scan_public_records(value, private_values)
    elif isinstance(records, list):
        for entry in records:
            scan_public_records(entry, private_values)
    elif isinstance(records, str):
        if BAD_STRING.search(records) or any(value and value.casefold() in records.casefold() for value in private_values):
            _fail("forbidden public data string")
    elif records is not None and type(records) not in (bool, int):
        _fail("invalid public record type")


def scan_frontend_text(text: str, private_values: tuple[str, ...] = ()) -> None:
    """Known-private matching decodes escaped literals; library token names aren't facts."""
    decoded = text
    # Decode common JS escapes without interpreting bytes as code or using eval.
    for _ in range(3):
        decoded = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m[1], 16)), decoded)
        decoded = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m[1], 16)), decoded)
    variants = [decoded, unquote(decoded)]
    for token in re.findall(r"[\"']([A-Za-z0-9+/_=-]{12,})[\"']", decoded):
        try:
            value = base64.b64decode(token.replace("-", "+").replace("_", "/") + "=" * (-len(token) % 4), validate=True)
            variants.append(value.decode("utf-8", errors="strict"))
        except (ValueError, UnicodeError):
            continue
    decoded = "\n".join(variants)
    if any(value and value.casefold() in decoded.casefold() for value in private_values):
        _fail("private value in frontend")
    denied = "|".join(re.escape(key) for key in sorted(DENIED_KEYS))
    if re.search(rf"[\"'](?:{denied})[\"']\s*:\s*(?:[\"']|[0-9]|\[|\{{)", decoded, re.IGNORECASE):
        _fail("forbidden serialized public metadata")
    if re.search(r"\b(?:source_id|source_name|source_url|credentials|provenance|collector|evidence_family|correlation_group|source_group|publication_proof|published_at|raw_evidence)\s*:\s*(?:[\"']|[0-9]|\[|\{)", decoded):
        _fail("forbidden serialized public metadata")


def verify_approval(approval: dict, source_catalog: bytes, rights_audit: bytes,
                    manifest: bytes, bundle_digest: str, evidence: bytes) -> None:
    if approval.get("public_release_approved") is not True:
        _fail("production approval denied")
    fields = {"source_catalog_sha256": sha256(source_catalog),
              "rights_audit_sha256": sha256(rights_audit),
              "release_manifest_sha256": sha256(manifest),
              "candidate_bundle_sha256": bundle_digest,
              "evidence_sha256": sha256(evidence)}
    if any(approval.get(key) != value for key, value in fields.items()):
        _fail("approval hash mismatch")
    record = parse_canonical(manifest)
    if record["mode"] != "production" or approval.get("release_id") != record["release_id"]:
        _fail("approval cannot promote synthetic or mismatched release")
    if not approval.get("approver") or not approval.get("approved_at"):
        _fail("approval attribution missing")
    # requirements booleans are never evidence. Future promotion must independently
    # validate every hosted report, capability report and the frozen candidate.
