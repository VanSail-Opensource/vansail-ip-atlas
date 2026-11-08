"""Executable build-private P0 admission/freshness contracts; no network actions."""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
import re

HEX = re.compile(r"^[0-9a-f]{64}$")
UTC_TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$")
LAYERS = ("exact", "explicit_prefix", "asn", "neighbors24")


def adapter_code_hash(root):
    internal = (root / "internal").resolve()
    if not internal.is_relative_to(root.resolve()) or not internal.is_dir():
        return ""
    digest = sha256()
    total = 0
    for path in sorted(internal.rglob("*.go")):
        if path.is_symlink() or not path.resolve().is_relative_to(internal):
            return ""
        total += path.stat().st_size
        if total > 64 * 1024 * 1024:
            return ""
        digest.update(path.relative_to(root).as_posix().encode("utf-8") + b"\0")
        digest.update(path.read_bytes() + b"\0")
    return digest.hexdigest()


def adapter_certified(source, root):
    path = root / "fixtures/source-certification/adapter-certifications.json"
    try:
        if path.stat().st_size > 1024 * 1024 or not path.resolve().is_relative_to(root.resolve()):
            return False
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate certification key")
                result[key] = value
            return result
        ledger = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)
        if set(ledger) != {"schema_version", "certifications"} or ledger["schema_version"] != 1:
            return False
        entries = ledger["certifications"]
        if not isinstance(entries, list) or len(entries) > 1000:
            return False
        ids = [entry["source_id"] for entry in entries]
        if len(set(ids)) != len(ids):
            return False
        for entry in entries:
            if entry["source_id"] != source["id"]:
                continue
            if set(entry) != {"source_id", "parser", "schema", "version", "fixture_sha256", "tested_at", "implementation_sha256"}:
                return False
            return (entry["parser"] == source["parser"]["id"] and entry["schema"] == source["parser"]["schema"]
                    and type(entry["version"]) is int and entry["version"] == source["parser"]["version"]
                    and HEX.fullmatch(entry["implementation_sha256"] or "") is not None
                    and entry["implementation_sha256"] == adapter_code_hash(root)
                    and entry["fixture_sha256"] == source["fixture"]["sha256"]
                    and entry["tested_at"] == source["fixture"]["tested_at"])
        return False
    except (OSError, ValueError, TypeError, KeyError):
        return False


def utc(value):
    if not isinstance(value, str) or not UTC_TIMESTAMP.fullmatch(value):
        raise ValueError("timestamp must be explicit UTC")
    return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(timezone.utc)


def fixture_issues(source, root: Path):
    fixture, parser = source["fixture"], source["parser"]
    issues = []
    if not adapter_certified(source, root):
        issues.append("reviewed_adapter_certification_required")
    if (fixture["status"] != "passed" or not fixture["schema_observed"]
            or not HEX.fullmatch(fixture["sha256"] or "") or fixture.get("synthetic") is not False):
        issues.append("observed_real_fixture_required")
    if (not parser["id"] or not parser["schema"] or parser["version"] is None
            or fixture.get("parser") != parser["id"] or fixture.get("schema") != parser["schema"]):
        issues.append("matching_certified_parser_required")
    try:
        utc(fixture["tested_at"])
    except (ValueError, TypeError):
        issues.append("fixture_test_time_required")
    path = fixture.get("path")
    if not path:
        issues.append("fixture_bytes_required")
    else:
        candidate = (root / path).resolve()
        private = (root / "fixtures" / "source-certification").resolve()
        if (not private.is_relative_to(root.resolve()) or not candidate.is_relative_to(private) or not candidate.is_file()
                or (root / path).is_symlink() or candidate.stat().st_size > 64 * 1024 * 1024):
            issues.append("controlled_fixture_path_required")
        elif sha256(candidate.read_bytes()).hexdigest() != fixture["sha256"]:
            issues.append("fixture_hash_mismatch")
    return issues


def static_issues(source, root: Path):
    issues = fixture_issues(source, root)
    rights, proof = source["license"], source["publication_proof"]
    if (rights["status"] != "reviewed" or rights["distribution"] != "allow"
            or rights.get("attribution_required") is not False
            or not rights.get("evidence_url") or not rights.get("review_basis")):
        issues.append("explicit_no_attribution_rights_required")
    if proof["kind"] == "unavailable" or not proof.get("locator") or not proof.get("field"):
        issues.append("payload_publication_proof_required")
    if not source.get("public_fields") or not source.get("field_mappings"):
        issues.append("explicit_public_field_mapping_required")
    if "reason_flags" in source.get("public_fields", []) and not source.get("signals"):
        issues.append("explicit_signal_mapping_required")
    download, discovery = source.get("download", {}), source.get("discovery", {})
    if not (download.get("url") or download.get("urls") or (
        isinstance(discovery, dict) and discovery.get("mode") == "latest-timestamped-asset"
    )) or download.get("format", "unknown") == "unknown":
        issues.append("exact_asset_and_parser_required")
    return sorted(set(issues))


@dataclass(frozen=True)
class Snapshot:
    """Trusted verifier result; P2 must bind this to actual hashed payload bytes.

    Fetch/HTTP/cache/local times cannot be supplied as a publication clock.
    Cached decisions must be rechecked against current policy every build.
    """
    payload_sha256: str
    proof_payload_sha256: str
    proof_kind: str
    published_at: str
    integrity_verified: bool
    schema_verified: bool
    immutable_commit_bound: bool = False
    item_published_at: str | None = None


def runtime_state(source, snapshot, now, root):
    if source["admission"] != "active":
        return "quarantined", ["not_active"]
    issues = static_issues(source, root)
    if issues:
        return "quarantined", issues
    if snapshot is None:
        return "missing", ["verified_payload_missing"]
    if not snapshot.integrity_verified or not snapshot.schema_verified:
        return "invalid", ["payload_integrity_or_schema_failed"]
    if (not HEX.fullmatch(snapshot.payload_sha256) or snapshot.payload_sha256 != snapshot.proof_payload_sha256
            or snapshot.proof_kind != source["publication_proof"]["kind"]):
        return "quarantined", ["publication_proof_not_payload_bound"]
    if snapshot.proof_kind == "github_commit" and not snapshot.immutable_commit_bound:
        return "quarantined", ["mutable_commit_not_proof"]
    # No authoritative header origins are allowlisted initially.
    if snapshot.proof_kind not in ("embedded", "github_release", "github_commit", "snapshot_metadata"):
        return "quarantined", ["unapproved_publication_clock"]
    try:
        publication = utc(snapshot.published_at)
        item = utc(snapshot.item_published_at) if snapshot.item_published_at else publication
    except (ValueError, TypeError):
        return "quarantined", ["unknown_publication_time"]
    if publication - now > timedelta(hours=24) or item - now > timedelta(hours=24):
        return "quarantined", ["publication_time_in_future"]
    expiry = publication + timedelta(hours=720)
    if source["category"] == "proxy_subscription_ip":
        if snapshot.item_published_at is None:
            return "quarantined", ["verified_item_publication_time_required"]
        expiry = min(expiry, publication + timedelta(hours=168), item + timedelta(hours=168))
    if now >= expiry:
        return "stale", ["publication_expired"]
    return "current", []


def capability_report(config, now, root, snapshots=None):
    snapshots = snapshots or {}
    decisions, eligible = [], []
    by_id = {s["id"]: s for s in config["sources"]}
    states = {sid: runtime_state(source, snapshots.get(sid), now, root) for sid, source in by_id.items()}
    resolved, visiting = {}, set()

    def resolve(sid):
        if sid in resolved:
            return resolved[sid]
        if sid in visiting or sid not in by_id:
            return "quarantined", ["invalid_dependency"]
        visiting.add(sid)
        state, issues = states[sid]
        if state == "current" and any(resolve(dep)[0] != "current" for dep in by_id[sid]["depends_on"]):
            state, issues = "quarantined", ["dependency_not_current"]
        visiting.remove(sid)
        resolved[sid] = state, issues
        return state, issues

    for source in config["sources"]:
        state, issues = resolve(source["id"])
        decisions.append({"id": source["id"], "admission": source["admission"], "runtime": state,
                          "blockers": sorted(set(issues + static_issues(source, root)))})
        if state == "current":
            eligible.append(source)

    def families(predicate):
        return sorted({s["evidence_family"] for s in eligible if predicate(s)})

    def fields(*names):
        return lambda s: set(names).issubset(s["public_fields"])

    country = families(lambda s: s["category"] == "geolocation" and fields("physical_country")(s) and s["coverage"]["kind"] == "mapping")
    city = families(lambda s: s["category"] == "geolocation" and s["coverage"]["kind"] == "mapping" and fields("physical_country", "region", "city")(s))
    coords = families(lambda s: s["category"] == "geolocation" and s["coverage"]["kind"] == "mapping" and fields("physical_country", "region", "city", "latitude", "longitude")(s))
    mapping = families(lambda s: s["category"] == "bgp" and s["scope"] == "prefix" and s["coverage"]["kind"] == "mapping" and fields("origins")(s))
    exact = families(lambda s: s["scope"] == "exact_ip" and bool(set(s["public_fields"]) & {"reason_flags", "usage_type"}))
    paths = families(lambda s: s["category"] == "bgp" and s["scope"] == "path" and fields("bgp_paths")(s))
    relations = families(lambda s: s["category"] == "bgp" and s["scope"] == "asn_edge" and fields("as_relationships")(s))
    complete = families(lambda s: s["category"] in ("abuse", "proxy", "proxy_ip", "proxy_subscription_ip")
                        and s["coverage"]["kind"] == "complete")
    layer_scopes = {"exact": "exact_ip", "neighbors24": "exact_ip", "explicit_prefix": "prefix", "asn": "asn"}
    complete_layers = {f: {layer for s in eligible if s["evidence_family"] == f and s["coverage"]["kind"] == "complete"
                          and s["category"] in ("abuse", "proxy", "proxy_ip", "proxy_subscription_ip")
                          and s["signals"] and "reason_flags" in s["public_fields"]
                          for layer in s.get("assessment_layers", []) if layer_scopes[layer] == s["scope"]} for f in complete}
    qualified = [f for f, layers in complete_layers.items() if set(LAYERS).issubset(layers)]
    reasons = ("malware", "botnet", "command_control", "abuse", "fraud", "scanning", "spam", "tor", "vpn", "proxy", "datacenter", "hosting")
    missing_reasons = [reason for reason in reasons if not families(lambda s: reason in s["signals"] and "reason_flags" in s["public_fields"])]
    usage = families(lambda s: s["category"] in ("infrastructure", "asn", "geolocation") and s["coverage"]["kind"] == "mapping" and fields("usage_type")(s))
    rpki = families(lambda s: s["category"] == "rpki" and s["scope"] == "prefix" and s["coverage"]["kind"] == "mapping" and fields("rpki_status")(s))
    rows = [
        ("country", bool(country), country, "one_current_mapping_family"),
        ("region_city", len(city) >= 2, city, "two_independent_city_mapping_families"),
        ("coordinates", len(coords) >= 2, coords, "two_independent_city_coordinate_families"),
        ("asn_prefix", bool(mapping), mapping, "current_multi_origin_mapping"),
        ("usage", bool(usage), usage, "direct_usage_evidence"),
        ("risk_reasons", not missing_reasons, [], "evidence_for_each_published_reason"),
        ("numeric_quality", len(qualified) >= 2, qualified, "two_complete_families_assessing_all_layers"),
        ("class_c", bool(exact), exact, "current_exact_observations"),
        ("rpki", bool(rpki), rpki, "current_vrp_data"),
        ("bgp_origins_paths", bool(mapping) and len(paths) >= 2, paths, "origins_and_two_path_families"),
        ("relationships", bool(relations), relations, "current_directed_relationships"),
        ("tier1", bool(relations) and len(paths) >= 2, sorted(set(paths + relations)), "relationships_and_two_path_families"),
        ("pages_release", False, [], "exact_artifact_hosted_preview_gates_and_approval_required"),
    ]
    capabilities = [{"capability": name, "status": "qualified" if ok else "blocked", "families": fs,
                     "requirement": requirement} for name, ok, fs, requirement in rows]
    return {"schema_version": 1, "build_private": True, "evaluated_at": now.isoformat().replace("+00:00", "Z"),
            "source_count": len(config["sources"]), "active_count": sum(s["admission"] == "active" for s in config["sources"]),
            "current_count": len(eligible), "production_eligible": all(ok for _, ok, _, _ in rows),
            "missing_reason_evidence": missing_reasons, "capabilities": capabilities, "sources": decisions}
