"""Closed, versioned configuration validation with bounded, unambiguous YAML."""
from __future__ import annotations

import json
import ipaddress
import math
from pathlib import Path
import re
from urllib.parse import urlsplit

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
CONFIG_NAMES = ("sources", "scoring", "tier1", "web", "release-approval")
MAX_CONFIG_BYTES = 2 * 1024 * 1024
FIELD_TARGETS = {
    "country_code": {"physical_country", "registration_country"},
    "allocation_country": {"registration_country"}, "region": {"region"}, "city": {"city"},
    "coordinates": {"latitude", "longitude", "coordinate_precision"},
    "asn": {"asn", "origins", "bgp_origins"}, "organization": {"organization"}, "isp": {"isp"},
    "handle": {"as_name"}, "description": {"organization"}, "country-code": {"asn_country"},
    "network_type": {"usage_type"}, "usage_type": {"usage_type"},
    "as_path": {"bgp_paths"}, "as_relationship": {"as_relationships"},
    "roa": {"rpki_status"}, "roa_asn": {"rpki_status"}, "roa_max_length": {"rpki_status"},
    **{field: {"reason_flags"} for field in (
        "abuse", "botnet_c2", "bruteforce", "compromised", "datacenter", "drop", "hosting", "proxy",
        "scan", "threat", "threat_count", "tor_exit", "vpn", "malware", "botnet", "c2", "fraud", "spam", "scanning"
    )},
}


class ContractError(ValueError):
    pass


class StrictLoader(yaml.SafeLoader):
    # Dates stay strings: schema validation and UTC parsing own their meaning.
    yaml_implicit_resolvers = {
        key: [(tag, rx) for tag, rx in values if tag != "tag:yaml.org,2002:timestamp"]
        for key, values in yaml.SafeLoader.yaml_implicit_resolvers.items()
    }

    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            raise ContractError("YAML aliases are forbidden")
        self.atlas_depth = getattr(self, "atlas_depth", 0) + 1
        if self.atlas_depth > 32:
            raise ContractError("YAML nesting exceeds 32")
        try:
            return super().compose_node(parent, index)
        finally:
            self.atlas_depth -= 1

    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in result:
                raise ContractError("duplicate or non-string YAML key")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def load_yaml(path: Path):
    if path.stat().st_size > MAX_CONFIG_BYTES:
        raise ContractError("configuration exceeds 2 MiB")
    try:
        return yaml.load(path.read_text(encoding="utf-8", errors="strict"), Loader=StrictLoader)
    except (yaml.YAMLError, UnicodeError, RecursionError) as exc:
        raise ContractError(f"invalid YAML in {path.name}") from exc


def validate_schema(name: str, value, root: Path = ROOT):
    def finite(node):
        if isinstance(node, float) and not math.isfinite(node):
            raise ContractError(f"{name}: nonfinite scalar")
        if isinstance(node, dict):
            for item in node.values():
                finite(item)
        elif isinstance(node, list):
            for item in node:
                finite(item)
    finite(value)
    schema = json.loads((root / "schemas" / f"{name}.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    errors = sorted(Draft202012Validator(schema).iter_errors(value), key=lambda e: str(list(e.path)))
    if errors:
        error = errors[0]
        # Never echo arbitrary YAML values, which could contain credentials.
        location = ".".join(str(part) for part in error.path)
        raise ContractError(f"{name}.{location}: violates {error.validator} contract")


def safe_https(value, *, allow_query=False):
    # urlsplit silently strips some control bytes. Reject the original spelling
    # first so different HTTP clients cannot reinterpret credentials or hosts.
    if (not isinstance(value, str) or any(ord(ch) <= 32 or ord(ch) == 127 for ch in value)
            or "\\" in value or "#" in value or (not allow_query and "?" in value)):
        return False
    try:
        url = urlsplit(value)
        if (url.scheme != "https" or not url.hostname or "@" in url.netloc
                or url.port not in (None, 443) or url.netloc.endswith(":")):
            return False
        hostname = url.hostname
        if "%" in hostname:  # percent-encoded hosts and IPv6 zone identifiers
            return False
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError:
            # This is only offline lexical validation. P2 must resolve *all*
            # destination addresses and revalidate every redirect/connection.
            labels = hostname.rstrip(".").split(".")
            if (len(hostname) > 253 or len(labels) < 2 or labels[-1].isdigit()
                    or re.fullmatch(r"(?:0x[0-9A-Fa-f]+|[0-9]+)(?:\.(?:0x[0-9A-Fa-f]+|[0-9]+))*", hostname)
                    or hostname.rstrip(".").endswith((".localhost", ".local", ".internal"))):
                return False
            return all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                       is not None for label in labels)
        return (address.is_global and not address.is_multicast and not address.is_reserved
                and not address.is_loopback and not address.is_link_local and not address.is_unspecified)
    except (ValueError, TypeError):
        return False


def validate_sources(config):
    sources = config["sources"]
    ids = [s["id"] for s in sources]
    if len(ids) != len(set(ids)):
        raise ContractError("duplicate source IDs")
    subscriptions = [s for s in sources if s["category"] == "proxy_subscription_ip"]
    if len(subscriptions) != 21:
        raise ContractError("catalog requires 21 subscription entries")
    for source in sources:
        sid = source["id"]
        dependencies = source["depends_on"]
        if any(dep not in ids or dep == sid for dep in dependencies):
            raise ContractError(f"{sid}: unresolved dependency")
        if source["scope"] != source["coverage"]["scope"]:
            raise ContractError(f"{sid}: coverage scope mismatch")
        layer_scopes = {"exact": "exact_ip", "neighbors24": "exact_ip", "explicit_prefix": "prefix", "asn": "asn"}
        if any(layer_scopes[layer] != source["scope"] for layer in source.get("assessment_layers", [])):
            raise ContractError(f"{sid}: assessment layer does not match evidence scope")
        if any(key not in source["fields"] for key in source["field_mappings"]):
            raise ContractError(f"{sid}: mapping references undeclared source field")
        for key, value in source["field_mappings"].items():
            values = value if isinstance(value, list) else [] if value is None else [value]
            if any(target not in source["public_fields"] or target not in FIELD_TARGETS.get(key, set()) for target in values):
                raise ContractError(f"{sid}: mapping bypasses field-specific normalization")
        if source["admission"] == "rights_approved" and (
            source["license"]["status"] != "reviewed" or source["license"]["distribution"] != "allow"
        ):
            raise ContractError(f"{sid}: invalid rights milestone")
        if "attribution" in source["license"]:
            from .policy import attribution_issues
            if attribution_issues(source["license"]["attribution"]):
                raise ContractError(f"{sid}: invalid reviewed dataset attribution")
        if source["fixture"]["status"] == "missing" and (
            source["fixture"]["sha256"] is not None or source["fixture"]["schema_observed"]
            or source["fixture"]["tested_at"] is not None
        ):
            raise ContractError(f"{sid}: missing fixture has certification data")
        if source["category"] == "proxy_subscription_ip" and (
            source["evidence_family"] != "public-subscription-aggregators"
            or source["fields"] != ["ip", "proxy"]
            or source.get("mapping", {}).get("literal_ip_only") is not True
        ):
            raise ContractError(f"{sid}: subscription family or literal-IP policy mismatch")
        discovery = source.get("discovery")
        for value in [source.get("repository"), source.get("download", {}).get("url"),
                      *source.get("download", {}).get("urls", []), source["license"].get("evidence_url"),
                      discovery.get("index_url") if isinstance(discovery, dict) else None]:
            if value is not None and not safe_https(value):
                raise ContractError(f"{sid}: unsafe source URL")
        proof = source["publication_proof"]
        if proof["locator"] is not None and proof["kind"] != "embedded" and not safe_https(
                proof["locator"], allow_query=True):
            raise ContractError(f"{sid}: unsafe publication-proof URL")
        if source["admission"] in ("fixture_tested", "active"):
            from .policy import fixture_issues
            if fixture_issues(source, ROOT):
                raise ContractError(f"{sid}: fixture milestone is not certified")
        if source["admission"] == "active":
            from .policy import static_issues
            if static_issues(source, ROOT):
                raise ContractError(f"{sid}: active admission gates failed")
    by_id = {s["id"]: s for s in sources}
    visiting, visited = set(), set()

    def visit(sid):
        if sid in visiting:
            raise ContractError("source dependency cycle")
        if sid in visited:
            return
        visiting.add(sid)
        for dep in by_id[sid]["depends_on"]:
            visit(dep)
        visiting.remove(sid)
        visited.add(sid)

    for sid in ids:
        visit(sid)
    bgp = config["build"]["bgp"]
    if bgp["relationship_classes"] != ["transit_upstream", "peer", "customer", "sibling", "unknown"]:
        raise ContractError("unresolved relationship alias")
    if bgp["max_mrt_sources_per_run"] < 2:
        raise ContractError("cold build cannot acquire two independent path families")
    caida = by_id["caida-asrel2"]
    if caida["download"].get("url") is not None or not isinstance(caida.get("discovery"), dict):
        raise ContractError("CAIDA requires deterministic current-snapshot discovery")


def load_configs(root: Path = ROOT):
    configs = {}
    paths = {path.stem for path in (root / "configs").glob("*.yaml")}
    if paths != set(CONFIG_NAMES):
        raise ContractError("unexpected or missing configuration files")
    for name in CONFIG_NAMES:
        config = load_yaml(root / "configs" / f"{name}.yaml")
        validate_schema(name, config, root)
        configs[name] = config
    validate_sources(configs["sources"])
    if configs["sources"]["build"]["bgp"]["relationship_classes"] != configs["tier1"]["relationships"]["classifications"]:
        raise ContractError("cross-config relationship enum mismatch")
    approval = configs["release-approval"]
    if approval["public_release_approved"]:
        from .policy import HEX, utc
        if not approval["approver"] or any(not HEX.fullmatch(approval.get(key) or "") for key in (
            "source_catalog_sha256", "rights_audit_sha256", "release_manifest_sha256", "release_id",
            "candidate_bundle_sha256", "evidence_sha256"
        )):
            raise ContractError("approval requires exact candidate hashes and approver")
        try:
            utc(approval["approved_at"])
        except (ValueError, TypeError) as exc:
            raise ContractError("approval requires UTC approval time") from exc
    return configs
