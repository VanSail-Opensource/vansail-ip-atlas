"""Closed global-credit artifacts; never VIA3 or per-query provenance.

These pure shape/integrity checks do not certify legal approval or inclusion.
Production callers must independently bind reviewed entries to included current
source receipts and the frozen candidate. The tree writer is synthetic-only.
"""
from __future__ import annotations

import ipaddress
import os
from pathlib import Path
import re
import stat
import tempfile
import unicodedata
from urllib.parse import urlsplit

from .contracts import ContractError, canonical_bytes, parse_canonical, sha256

MAX_ENTRIES = 256
MAX_DOCUMENT_BYTES = 1024 * 1024
MAX_INDEX_BYTES = 4096
INDEX_PATH = "dataset-credits.json"
HASH = re.compile(r"[0-9a-f]{64}\Z")
CREDIT_PATH = re.compile(r"/_atlas/credits/([0-9a-f]{64})\.json\Z")
SECRET = re.compile(r"(?:vless|vmess|trojan|ssr?|hy2?|hysteria2?|tuic|anytls)://|"
                    r"-----BEGIN[^\r\n]*PRIVATE KEY-----|gh[pousr]_|github_pat_", re.IGNORECASE)
SPECIAL_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    "0.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15",
    "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
    "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20",
))


def _reject() -> None:
    raise ContractError("invalid global dataset credits")


def _hash(value: object) -> bool:
    return isinstance(value, str) and HASH.fullmatch(value) is not None


def _text(value: object, maximum: int) -> bool:
    return (isinstance(value, str) and 1 <= len(value) <= maximum
            and value.strip() == value and unicodedata.normalize("NFC", value) == value
            and SECRET.search(value) is None
            and all(unicodedata.category(ch) not in ("Cc", "Cf", "Cs") for ch in value))


def _public_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    if (not address.is_global or address.is_multicast or address.is_reserved
            or address.is_loopback or address.is_link_local or address.is_unspecified):
        return False
    if any(address.version == network.version and address in network for network in SPECIAL_NETWORKS):
        return False
    return address.version == 4 or address in ipaddress.ip_network("2000::/3")


def _url(value: object) -> bool:
    if (not isinstance(value, str) or not 1 <= len(value) <= 2048
            or not value.startswith("https://") or not value.isascii()
            or SECRET.search(value) is not None
            or any(ord(ch) <= 32 or ord(ch) == 127 or ch in "\\?#<>\"'" for ch in value)
            or re.search(r"%(?![0-9a-fA-F]{2})", value)):
        return False
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        if (parsed.scheme != "https" or not host or parsed.username is not None
                or parsed.password is not None or parsed.port not in (None, 443)
                or parsed.port is not None and parsed.netloc.rsplit(":", 1)[1] != "443"
                or parsed.netloc.endswith(":") or "%" in host):
            return False
        try:
            return _public_address(ipaddress.ip_address(host))
        except ValueError:
            labels = host.split(".")
            return (len(host) <= 253 and len(labels) >= 2
                    and not all(re.fullmatch(r"(?:[0-9]+|0x[0-9a-f]+)", label) for label in labels)
                    and not host.endswith((".localhost", ".local", ".internal"))
                    and any("a" <= ch <= "z" for ch in labels[-1])
                    and all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                            is not None for label in labels))
    except (ValueError, TypeError):
        return False


def _entry(value: object) -> dict:
    required = {"name", "text", "url"}
    if (type(value) is not dict or not required <= set(value)
            or set(value) - required - {"license_url"}
            or not _text(value["name"], 128) or not _text(value["text"], 2048)
            or not _url(value["url"]) or "license_url" in value and not _url(value["license_url"])):
        _reject()
    # Copy reviewed fields without normalizing or inventing legal notice bytes.
    return dict(value)


def build_credit_document(release_id: str, mode: str, entries: list[dict]) -> bytes:
    """Canonicalize/deduplicate reviewed-shaped notices; never authorize a source."""
    if (not _hash(release_id) or mode not in ("synthetic", "production")
            or type(entries) is not list or len(entries) > MAX_ENTRIES
            or mode == "synthetic" and entries):
        _reject()
    unique = {}
    for value in entries:
        entry = _entry(value)
        unique[canonical_bytes(entry)] = entry
    document = {"format_version": 1, "release_id": release_id, "mode": mode,
                "entries": [unique[key] for key in sorted(unique)]}
    data = canonical_bytes(document)
    if len(data) > MAX_DOCUMENT_BYTES:
        _reject()
    return data


def _release_modes(current_id: str, modes: dict[str, str]) -> None:
    if (not _hash(current_id) or type(modes) is not dict or not 1 <= len(modes) <= 2
            or current_id not in modes or any(not _hash(key) or value not in ("synthetic", "production")
                                             for key, value in modes.items())):
        _reject()


def _link(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0)
                                           & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def _path(public: Path, relative: str) -> Path:
    """Do not follow symlinks/junctions in any owned path component."""
    target = public
    parts = relative.split("/")
    if not parts or any(not part or part in (".", "..") or "\\" in part or ":" in part for part in parts):
        _reject()
    for position, part in enumerate([None, *parts]):
        if part is not None:
            target = target / part
        try:
            info = target.lstat()
        except FileNotFoundError:
            continue
        if _link(info) or position < len(parts) and not stat.S_ISDIR(info.st_mode):
            _reject()
    return target


def _read(public: Path, relative: str, limit: int) -> bytes:
    target = _path(public, relative)
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        with os.fdopen(os.open(target, flags), "rb") as stream:
            info = os.fstat(stream.fileno())
            if _link(info) or not stat.S_ISREG(info.st_mode) or not 1 <= info.st_size <= limit:
                _reject()
            data = stream.read(limit + 1)
    except OSError as error:
        raise ContractError("missing or unsafe dataset credit artifact") from error
    if len(data) > limit:
        _reject()
    return data


def _parse(data: bytes) -> object:
    try:
        return parse_canonical(data)
    except (ValueError, TypeError, RecursionError) as error:
        raise ContractError("noncanonical dataset credit artifact") from error


def _credit_files(public: Path) -> set[str]:
    directory = _path(public, "_atlas/credits")
    try:
        if not directory.is_dir():
            _reject()
        files = set()
        for child in directory.iterdir():
            info = child.lstat()
            if _link(info) or not stat.S_ISREG(info.st_mode) or not CREDIT_PATH.fullmatch("/_atlas/credits/" + child.name):
                _reject()
            files.add("_atlas/credits/" + child.name)
            if len(files) > 2:
                _reject()
        return files
    except OSError as error:
        raise ContractError("missing or unsafe dataset credit directory") from error


def validate_credit_tree(public: Path, current_id: str, release_modes: dict[str, str]) -> set[str]:
    """Return only exact validated relative paths eligible for scanner exemption.

    This validates shape, identity and integrity. Production inclusion/notice
    completeness is an additional private receipt/approval gate of the caller.
    """
    _release_modes(current_id, release_modes)
    index = _parse(_read(public, INDEX_PATH, MAX_INDEX_BYTES))
    if (type(index) is not dict or set(index) != {"format_version", "current_release_id", "releases"}
            or type(index["format_version"]) is not int or index["format_version"] != 1
            or index["current_release_id"] != current_id or type(index["releases"]) is not list
            or len(index["releases"]) != len(release_modes)):
        _reject()
    release_ids, paths = [], set()
    for item in index["releases"]:
        if (type(item) is not dict or set(item) != {"release_id", "credits_path", "credits_sha256"}
                or not _hash(item["release_id"]) or item["release_id"] not in release_modes
                or not _hash(item["credits_sha256"])):
            _reject()
        release_id, digest = item["release_id"], item["credits_sha256"]
        expected_path = f"/_atlas/credits/{digest}.json"
        if item["credits_path"] != expected_path:
            _reject()
        relative = expected_path[1:]
        data = _read(public, relative, MAX_DOCUMENT_BYTES)
        if sha256(data) != digest:
            _reject()
        document = _parse(data)
        if (type(document) is not dict or set(document) != {"format_version", "release_id", "mode", "entries"}
                or type(document["format_version"]) is not int or document["format_version"] != 1
                or document["release_id"] != release_id or document["mode"] != release_modes[release_id]
                or build_credit_document(release_id, document["mode"], document["entries"]) != data):
            _reject()
        release_ids.append(release_id)
        paths.add(relative)
    if release_ids != sorted(release_modes) or _credit_files(public) != paths:
        _reject()
    return {INDEX_PATH, *paths}


def _write(public: Path, relative: str, data: bytes) -> None:
    target = _path(public, relative)
    if relative.startswith("_atlas/credits/") and target.exists():
        if _read(public, relative, MAX_DOCUMENT_BYTES) != data:
            _reject()
        return  # Never overwrite conflicting bytes under an immutable hash path.
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=target.parent, prefix=".dataset-credit-", delete=False) as output:
            temporary = Path(output.name)
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, target)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def write_synthetic_credit_tree(public: Path, current_id: str, release_modes: dict[str, str]) -> set[str]:
    """Write only empty synthetic documents; cannot emit a production credit tree."""
    _release_modes(current_id, release_modes)
    if any(mode != "synthetic" for mode in release_modes.values()):
        _reject()
    documents, releases = {}, []
    for release_id in sorted(release_modes):
        data = build_credit_document(release_id, "synthetic", [])
        digest = sha256(data)
        relative = f"_atlas/credits/{digest}.json"
        documents[relative] = data
        releases.append({"release_id": release_id, "credits_path": "/" + relative, "credits_sha256": digest})
    # Reject preexisting unknown files; do not clear arbitrary paths to hide them.
    directory = _path(public, "_atlas/credits")
    if directory.exists() and not _credit_files(public) <= set(documents):
        _reject()
    index = canonical_bytes({"format_version": 1, "current_release_id": current_id, "releases": releases})
    for relative, data in documents.items():
        _write(public, relative, data)
    _write(public, INDEX_PATH, index)
    return validate_credit_tree(public, current_id, release_modes)
