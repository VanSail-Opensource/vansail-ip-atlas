"""Canonicalize only pinned Nuxt operational timestamps, preserving other bytes."""
from __future__ import annotations

import json
from pathlib import Path
import re

from tools.release_contract.contracts import ContractError

SCRIPT = re.compile(r"<script\b([^>]*)>([\s\S]*?)</script\s*>", re.IGNORECASE)
NUXT_ID = re.compile(r"(?<![\w-])(?i:id)\s*=\s*([\"'])__NUXT_DATA__\1")
DECODER = json.JSONDecoder()


def _load(text: str) -> object:
    def unique(pairs: list) -> dict:
        result = {}
        for key, value in pairs:
            if key in result:
                raise ContractError("duplicate framework metadata key")
            result[key] = value
        return result
    return json.loads(text, object_pairs_hook=unique)


def _skip(text: str, position: int) -> int:
    while position < len(text) and text[position] in " \r\n\t":
        position += 1
    return position


def _table_value_span(text: str, target: int) -> tuple[int, int]:
    position = _skip(text, 0)
    if position >= len(text) or text[position] != "[":
        raise ContractError("unexpected Nuxt payload table")
    position += 1
    index = 0
    while True:
        position = _skip(text, position)
        if position >= len(text) or text[position] == "]":
            raise ContractError("missing Nuxt operational timestamp index")
        start = position
        _, end = DECODER.raw_decode(text, position)
        if index == target:
            return start, end
        position = _skip(text, end)
        if position >= len(text) or text[position] != ",":
            raise ContractError("unexpected Nuxt payload table separator")
        position += 1
        index += 1


def _reference_count(values: list, target: int) -> int:
    def count(value: object) -> int:
        if type(value) is int:
            return int(value == target)
        if isinstance(value, dict):
            return sum(count(item) for item in value.values())
        if isinstance(value, list):
            return sum(count(item) for item in value)
        return 0
    # Table primitives are values; numeric children inside table objects/arrays
    # are references. Never overwrite a number shared with a fact/state field.
    return sum(count(value) for value in values if isinstance(value, (dict, list)))


def normalize_payload(text: str, epoch_ms: int) -> str:
    try:
        values = _load(text)
    except (ValueError, UnicodeError) as error:
        raise ContractError("invalid Nuxt payload JSON") from error
    if not isinstance(values, list) or not values or not isinstance(values[0], dict):
        raise ContractError("unexpected Nuxt payload metadata schema")
    if "prerenderedAt" not in values[0]:
        return text
    target = values[0]["prerenderedAt"]
    if (type(target) is not int or not 0 < target < len(values)
            or type(values[target]) is not int or not 0 <= values[target] <= 2**53 - 1
            or _reference_count(values, target) != 1):
        raise ContractError("shared or invalid Nuxt operational timestamp reference")
    start, end = _table_value_span(text, target)
    return text[:start] + str(epoch_ms) + text[end:]


def normalize_build_metadata(text: str, epoch_ms: int, *, expected_id: str | None) -> str:
    try:
        value = _load(text)
    except ValueError as error:
        raise ContractError("invalid Nuxt build metadata") from error
    keys = {"id", "timestamp"} if expected_id is None else {"id", "timestamp", "prerendered"}
    if (not isinstance(value, dict) or set(value) != keys or not isinstance(value["id"], str)
            or not re.fullmatch(r"[a-zA-Z0-9_-]{1,100}", value["id"])
            or type(value["timestamp"]) is not int or not 0 <= value["timestamp"] <= 2**53 - 1
            or expected_id is not None and value["id"] != expected_id
            or "prerendered" in value and (not isinstance(value["prerendered"], list)
                or any(not isinstance(route, str) or not route.startswith("/ip") or "?" in route or "#" in route
                       for route in value["prerendered"]))):
        raise ContractError("unexpected Nuxt build metadata schema")
    # Find the top-level timestamp token with the JSON parser. This preserves
    # escaping, key order, strings and all non-operational numeric bytes.
    position = _skip(text, 0) + 1
    while True:
        position = _skip(text, position)
        key, end = DECODER.raw_decode(text, position)
        position = _skip(text, end)
        if position >= len(text) or text[position] != ":":
            raise ContractError("invalid Nuxt build metadata separator")
        start = _skip(text, position + 1)
        _, end = DECODER.raw_decode(text, start)
        if key == "timestamp":
            return text[:start] + str(epoch_ms) + text[end:]
        position = _skip(text, end)
        if position >= len(text) or text[position] != ",":
            raise ContractError("missing Nuxt build timestamp")
        position += 1


def canonicalize_operational_times(public: Path, valid_from: int) -> int:
    if type(valid_from) is not int or not 0 <= valid_from <= (2**53 - 1) // 1000:
        raise ContractError("release evaluation clock cannot encode Nuxt milliseconds")
    epoch_ms = valid_from * 1000
    modified = 0
    for path in public.rglob("_payload.json"):
        # Only framework payloads under the implemented prerendered route tree.
        relative = path.relative_to(public).parts
        if not relative or relative[0] != "ip":
            raise ContractError("unexpected framework payload location")
        original = path.read_bytes().decode("utf-8", errors="strict")
        normalized = normalize_payload(original, epoch_ms)
        if normalized != original:
            path.write_bytes(normalized.encode("utf-8"))
            modified += 1
    for path in public.rglob("*.html"):
        original = path.read_bytes().decode("utf-8", errors="strict")
        def replace(match: re.Match) -> str:
            if not NUXT_ID.search(match[1]):
                return match[0]
            normalized = normalize_payload(match[2], epoch_ms)
            offset = match.start(2) - match.start(0)
            return match[0][:offset] + normalized + match[0][offset + len(match[2]):]
        normalized = SCRIPT.sub(replace, original)
        if normalized != original:
            path.write_bytes(normalized.encode("utf-8"))
            modified += 1
    build_root = public / "_nuxt/builds"
    if build_root.exists():
        paths = [build_root / "latest.json", *sorted((build_root / "meta").glob("*.json"))]
        for path in paths:
            original = path.read_bytes().decode("utf-8", errors="strict")
            normalized = normalize_build_metadata(original, epoch_ms,
                expected_id=None if path.name == "latest.json" else path.stem)
            if normalized != original:
                path.write_bytes(normalized.encode("utf-8"))
                modified += 1
    return modified
