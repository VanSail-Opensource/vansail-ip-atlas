"""Bind the browser memory workload's measured populations to its actual bytes.

This verifier inspects compressed envelopes without decompressing in Python.
The exact emitted worker must independently validate every fetched shard's
decoded section checksums and records while producing the reported answers.
"""
from __future__ import annotations

from pathlib import Path
import re
import struct

from tools.release_contract.contracts import ContractError, canonical_bytes, parse_canonical, sha256

BUDGETS = {"decoded_object_bytes": 32 << 20, "live_decoded_bytes": 96 << 20,
           "answer_bytes": 8 << 20, "decoder_window_bytes": 8 << 20}
SECTIONS = {1: (1, 2, 3, 4, 7), 2: (1, 3, 7, 8), 4: (1, 3, 4, 7, 8),
            5: (1, 3, 8), 8: (2, 3, 7, 11, 12), 11: (2, 3, 4, 9),
            13: (2, 3), 14: (5, 6)}


def require(condition: bool, detail: str) -> None:
    if not condition:
        raise ContractError("memory profile: " + detail)


def _frame_window(frame: memoryview, decoded: int) -> int:
    require(9 <= len(frame) < 24 << 20 and bytes(frame[:4]) == b"\x28\xb5\x2f\xfd", "frame envelope")
    descriptor = frame[4]
    require(descriptor & 0x1b == 0 and descriptor & 4 != 0, "frame flags")
    single = bool(descriptor & 0x20)
    offset, window = 5, 0
    if not single:
        value = frame[offset]
        offset += 1
        base = 1 << (10 + (value >> 3))
        window = base + base // 8 * (value & 7)
    flag = descriptor >> 6
    size_bytes = (1 if single else 0) if flag == 0 else 1 << flag
    require(size_bytes > 0 and offset + size_bytes <= len(frame), "frame content size")
    size = int.from_bytes(frame[offset:offset + size_bytes], "little") + (256 if flag == 1 else 0)
    offset += size_bytes
    require(size == decoded, "frame declared output differs")
    if single:
        window = size
    require(0 < window <= BUDGETS["decoder_window_bytes"], "frame window")
    while True:
        require(offset + 3 <= len(frame), "truncated block")
        block = int.from_bytes(frame[offset:offset + 3], "little")
        offset += 3
        kind, size = (block >> 1) & 3, block >> 3
        require(kind != 3 and size <= min(128 << 10, window), "block bounds")
        encoded = 1 if kind == 1 else size
        require(offset + encoded <= len(frame), "truncated block payload")
        offset += encoded
        if block & 1:
            break
    require(offset + 4 == len(frame), "frame checksum envelope or trailing bytes")
    return window


def inspect_object(data: bytes) -> dict:
    """Return actual container/window metrics; do not trust profile declarations."""
    require(64 <= len(data) < 24 << 20, "object length")
    require(data[:4] == b"VIA3" and struct.unpack_from("<HHH", data, 4) == (3, 5, 64), "object version")
    kind = struct.unpack_from("<H", data, 10)[0]
    require(kind in SECTIONS and data[12:16] == bytes(4) and data[44] == 1 and data[45:64] == bytes(19), "object header")
    count = struct.unpack_from("<I", data, 16)[0]
    table, length, decoded_total = struct.unpack_from("<QQQ", data, 20)
    require(table == 64 and length == len(data) and 0 < decoded_total <= BUDGETS["decoded_object_bytes"], "object bounds")
    require(count == len(SECTIONS[kind]) and 64 + count * 64 <= len(data), "section count")
    end, total, largest_window = 64 + count * 64, 0, 0
    for index, expected_id in enumerate(SECTIONS[kind]):
        descriptor = memoryview(data)[64 + index * 64:128 + index * 64]
        section_id = struct.unpack_from("<H", descriptor)[0]
        offset, length, decoded = struct.unpack_from("<QQQ", descriptor, 8)
        require(section_id == expected_id and descriptor[2] == 1 and bytes(descriptor[3:8]) == bytes(5), "section schema")
        require(offset == end and 0 < length <= len(data) - end and 8 <= decoded <= decoded_total - total, "section bounds")
        largest_window = max(largest_window, _frame_window(memoryview(data)[offset:offset + length], decoded))
        end += length
        total += decoded
    require(end == len(data) and total == decoded_total, "section totals")
    return {"sha256": sha256(data), "kind": kind, "decoded_bytes": total, "decoder_window_bytes": largest_window}


def _verify_observation(profile: dict, observed: dict, objects: dict[str, dict]) -> None:
    require(type(observed) is dict and observed.get("errors") == [] and observed.get("completed_cases") == 3, "workload did not complete")
    cases = profile.get("cases")
    measured = observed.get("cases")
    require(type(cases) is list and len(cases) == 3 and type(measured) is list and len(measured) == 3, "case population")
    expected = (("maximum-materialized-answer", "203.0.113.1", {1, 4, 8, 11, 13, 14}),
                ("maximum-live-decoded", "203.0.113.250", {1, 2, 5}),
                ("live-limit-rejection", "203.0.113.2", {1, 2, 4}))
    fetched = observed.get("object_hashes")
    require(type(fetched) is list and all(type(v) is str for v in fetched) and len(set(fetched)) == len(fetched), "fetched object population")
    require(set(fetched) == set(objects), "workload did not fetch the exact object population")
    for index, (name, query, kinds) in enumerate(expected):
        case, result = cases[index], measured[index]
        require(type(case) is dict and type(result) is dict and case.get("name") == name and result.get("name") == name,
                "case identity or order")
        require(case.get("q") == query and case.get("action") == "lookup", "case query")
        hashes = case.get("required_objects")
        require(type(hashes) is list and all(type(v) is str and v in objects for v in hashes) and len(set(hashes)) == len(hashes), "required object references")
        require({objects[digest]["kind"] for digest in hashes} == kinds and len(hashes) == len(kinds), "required object kinds")
        require(set(hashes).issubset(fetched), "required object not requested")
        expected_bytes = 0 if index == 2 else case.get("answer_bytes")
        require(type(expected_bytes) is int and 0 <= expected_bytes <= BUDGETS["answer_bytes"], "answer declaration")
        for key in ("answer_bytes", "repeat_answer_bytes"):
            require(type(result.get(key)) is int and result[key] == expected_bytes, "materialized or repeated answer differs")
        require(result.get("retained_answers") == 1, "maximum answer was not retained")
        require(case.get("retain_answer", False) is (index == 0), "retained case")
        require(case.get("expected_error") == ("resource_limit" if index == 2 else None), "limit rejection")
    require(cases[0]["answer_bytes"] == BUDGETS["answer_bytes"] and 0 < cases[1]["answer_bytes"] < BUDGETS["answer_bytes"], "answer boundary not attained")
    require(sum(objects[digest]["decoded_bytes"] for digest in cases[1]["required_objects"]) == BUDGETS["live_decoded_bytes"], "live population sum")
    require(observed.get("retained_answer_bytes") == [BUDGETS["answer_bytes"]], "retained answer must be touched after all cases")


def verify_memory_profile(profile: dict, observed: dict, fixture_root: Path) -> None:
    require(type(profile) is dict and profile.get("schema_version") == 1 and profile.get("scope") == "accepted-worst-case-browser-profile", "identity")
    for field in ("budgets", "coverage"):
        value = profile.get(field)
        require(type(value) is dict and value == BUDGETS and all(type(v) is int for v in value.values()), "boundary coverage")
    release_id = profile.get("release_id")
    require(type(release_id) is str and re.fullmatch(r"[a-f0-9]{64}", release_id) is not None, "release identity")
    pointer = parse_canonical((fixture_root / "current.json").read_bytes())
    manifest_bytes = (fixture_root / "releases" / release_id / "manifest.json").read_bytes()
    manifest = parse_canonical(manifest_bytes)
    require(type(pointer) is dict and pointer == {"format_version": 3, "release_id": release_id,
            "manifest_path": f"/_atlas/releases/{release_id}/manifest.json", "manifest_sha256": sha256(manifest_bytes)}, "pointer binding")
    require(type(manifest) is dict and manifest.get("release_id") == release_id and manifest.get("mode") == "synthetic"
            and manifest.get("format_version") == 3 and manifest.get("schema_version") == 5 and manifest.get("codec") == "zstd-1", "synthetic manifest")
    descriptor = {key: value for key, value in manifest.items() if key != "release_id"}
    require(sha256(canonical_bytes(descriptor)) == release_id, "descriptor binding")
    entries = manifest.get("objects")
    require(type(entries) is list and len(entries) == len(SECTIONS), "manifest population")
    actual = {}
    for entry in entries:
        require(type(entry) is dict and type(entry.get("sha256")) is str and re.fullmatch(r"[a-f0-9]{64}", entry["sha256"]) is not None, "object identity")
        digest = entry["sha256"]
        data = (fixture_root / "objects" / (digest + ".via3")).read_bytes()
        metric = inspect_object(data)
        require(digest not in actual and digest == metric["sha256"] and entry.get("bytes") == len(data) and entry.get("kind") == metric["kind"], "object binding")
        actual[digest] = metric
    require({entry["kind"] for entry in actual.values()} == set(SECTIONS), "object kinds")
    declared = profile.get("objects")
    require(type(declared) is list and declared == [actual[key] for key in sorted(actual)], "declared metrics differ from bytes")
    require(max(row["decoded_bytes"] for row in actual.values()) == BUDGETS["decoded_object_bytes"]
            and max(row["decoder_window_bytes"] for row in actual.values()) == BUDGETS["decoder_window_bytes"], "object and window boundaries not attained")
    _verify_observation(profile, observed, actual)
