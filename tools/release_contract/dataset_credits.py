"""Closed global-credit artifacts; never VIA3 or per-query provenance.

These pure shape/integrity checks do not certify legal approval or inclusion.
Production callers must independently bind reviewed entries to included current
source receipts and the frozen candidate before calling the explicit tree writer.
"""
from __future__ import annotations

import ipaddress
import os
from pathlib import Path
import re
import stat
import tempfile
import unicodedata
import struct
import zlib
from urllib.parse import urlsplit

from .contracts import ContractError, canonical_bytes, parse_canonical, sha256

MAX_ENTRIES = 256
MAX_DOCUMENT_BYTES = 1024 * 1024
MAX_INDEX_BYTES = 4096
MAX_LOGO_BYTES = 256 * 1024
LOGO_PATH = re.compile(r"/_atlas/legal/([0-9a-f]{64})\.png\Z")
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
            or set(value) - required - {"license_url", "logo"}
            or not _text(value["name"], 128) or not _text(value["text"], 2048)
            or not _url(value["url"]) or "license_url" in value and not _url(value["license_url"])):
        _reject()
    if "logo" in value:
        logo = value["logo"]
        if (type(logo) is not dict or set(logo) != {"path", "sha256", "alt"}
                or not _hash(logo["sha256"]) or logo["path"] != f"/_atlas/legal/{logo['sha256']}.png"
                or not _text(logo["alt"], 128)):
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
    document = {"format_version": 2, "release_id": release_id, "mode": mode,
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


def validate_logo(data: bytes, digest: str) -> None:
    """Bounded PNG artwork; only symmetric numeric density metadata is allowed."""
    if len(data) > MAX_LOGO_BYTES or sha256(data) != digest or data[:8] != b"\x89PNG\r\n\x1a\n":
        _reject()
    pos, chunks, compressed = 8, [], bytearray()
    width = height = channels = 0
    while pos + 12 <= len(data):
        size = struct.unpack_from(">I", data, pos)[0]
        kind = data[pos + 4:pos + 8]
        if size > MAX_LOGO_BYTES or pos + size + 12 > len(data):
            _reject()
        payload = data[pos + 8:pos + 8 + size]
        if kind not in (b"IHDR", b"pHYs", b"IDAT", b"IEND"):
            _reject()
        if zlib.crc32(kind + payload) & 0xffffffff != struct.unpack_from(">I", data, pos + size + 8)[0]:
            _reject()
        if kind == b"IHDR":
            if chunks or size != 13:
                _reject()
            width, height, depth, color, compression, filtering, interlace = struct.unpack(">IIBBBBB", payload)
            channels = {0: 1, 2: 3, 4: 2, 6: 4}.get(color, 0)
            if not 1 <= width <= 512 or not 1 <= height <= 512 or depth != 8 or not channels or compression or filtering or interlace:
                _reject()
        elif not chunks:
            _reject()
        if kind == b"pHYs":
            if chunks != [b"IHDR"] or size != 9:
                _reject()
            x, y, unit = struct.unpack(">IIB", payload)
            if not 1 <= x <= 40000 or x != y or unit != 1:
                _reject()
        if kind == b"IDAT":
            compressed.extend(payload)
        if kind == b"IEND" and (size or pos + 12 != len(data)):
            _reject()
        chunks.append(kind)
        pos += size + 12
    if pos != len(data) or not chunks or chunks[-1] != b"IEND" or not compressed:
        _reject()
    expected = height * (1 + width * channels)
    decoder = zlib.decompressobj()
    try:
        pixels = decoder.decompress(bytes(compressed), expected + 1)
    except zlib.error:
        _reject()
    if len(pixels) != expected or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail or any(pixels[i] > 4 for i in range(0, expected, 1 + width * channels)):
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
    release_ids, paths, logos = [], set(), set()
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
                or type(document["format_version"]) is not int or document["format_version"] != 2
                or document["release_id"] != release_id or document["mode"] != release_modes[release_id]
                or build_credit_document(release_id, document["mode"], document["entries"]) != data):
            _reject()
        release_logos = {}
        for entry in document["entries"]:
            if "logo" in entry:
                logo = entry["logo"]
                relative_logo = logo["path"][1:]
                logo_data = _read(public, relative_logo, MAX_LOGO_BYTES)
                validate_logo(logo_data, logo["sha256"])
                release_logos[relative_logo] = len(logo_data)
                logos.add(relative_logo)
        if len(release_logos) > 32 or sum(release_logos.values()) > 4 * 1024 * 1024:
            _reject()
        release_ids.append(release_id)
        paths.add(relative)
    if release_ids != sorted(release_modes) or _credit_files(public) != paths:
        _reject()
    directory = _path(public, "_atlas/legal")
    if directory.exists():
        actual = set()
        for child in directory.iterdir():
            if _link(child.lstat()) or not child.is_file() or not LOGO_PATH.fullmatch("/_atlas/legal/" + child.name):
                _reject()
            actual.add("_atlas/legal/" + child.name)
        if actual != logos:
            _reject()
    elif logos:
        _reject()
    return {INDEX_PATH, *paths, *logos}


def _write(public: Path, relative: str, data: bytes) -> None:
    target = _path(public, relative)
    if relative.startswith(("_atlas/credits/", "_atlas/legal/")) and target.exists():
        limit = MAX_LOGO_BYTES if relative.startswith("_atlas/legal/") else MAX_DOCUMENT_BYTES
        if _read(public, relative, limit) != data:
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
    return write_credit_tree(public, current_id, release_modes, {key: [] for key in release_modes})


def write_credit_tree(public: Path, current_id: str, release_modes: dict[str, str],
                      entries_by_release: dict[str, list[dict]], *, logo_root: Path | None = None) -> set[str]:
    """Serialize exact qualified inclusion notices; this pure writer grants no rights."""
    _release_modes(current_id, release_modes)
    if type(entries_by_release) is not dict or set(entries_by_release) != set(release_modes):
        _reject()
    documents, releases = {}, []
    logo_documents = {}
    for release_id in sorted(release_modes):
        data = build_credit_document(release_id, release_modes[release_id], entries_by_release[release_id])
        digest = sha256(data)
        relative = f"_atlas/credits/{digest}.json"
        documents[relative] = data
        releases.append({"release_id": release_id, "credits_path": "/" + relative, "credits_sha256": digest})
        release_logos = {}
        for entry in entries_by_release[release_id]:
            if "logo" in entry:
                logo = entry["logo"]
                if logo_root is None:
                    _reject()
                data_logo = _read(logo_root, logo["sha256"] + ".png", MAX_LOGO_BYTES)
                validate_logo(data_logo, logo["sha256"])
                release_logos[logo["path"][1:]] = data_logo
        if len(release_logos) > 32 or sum(map(len, release_logos.values())) > 4 * 1024 * 1024:
            _reject()
        logo_documents.update(release_logos)
    # Reject preexisting unknown files; do not clear arbitrary paths to hide them.
    directory = _path(public, "_atlas/credits")
    if directory.exists() and not _credit_files(public) <= set(documents):
        _reject()
    directory = _path(public, "_atlas/legal")
    if directory.exists():
        for child in directory.iterdir():
            relative = "_atlas/legal/" + child.name
            if _link(child.lstat()) or not child.is_file() or relative not in logo_documents:
                _reject()
    # Validate every immutable target before changing the mutable index.
    for relative, data in {**documents, **logo_documents}.items():
        if _path(public, relative).exists() and _read(public, relative, MAX_DOCUMENT_BYTES) != data:
            _reject()
    index = canonical_bytes({"format_version": 1, "current_release_id": current_id, "releases": releases})
    for relative, data in {**documents, **logo_documents}.items():
        _write(public, relative, data)
    _write(public, INDEX_PATH, index)
    return validate_credit_tree(public, current_id, release_modes)
