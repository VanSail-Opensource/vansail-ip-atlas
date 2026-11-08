"""Generate source-free P0 contract vectors; never reads source-samples."""

import json
import struct
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "fixtures" / "contracts"


def put(name, value):
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def queries():
    inputs = []
    def good(text, kind, canonical):
        inputs.append({"input": text, "expected": {"kind": kind, "canonical": canonical}})
    def bad(text):
        inputs.append({"input": text, "error": "invalid_input"})
    for text, canonical in [
        ("1.1.1.1", "1.1.1.1"), (" 8.8.8.8\t", "8.8.8.8"),
        ("0.0.0.0", "0.0.0.0"), ("255.255.255.255", "255.255.255.255"),
        ("10.0.0.1", "10.0.0.1"), ("127.0.0.1", "127.0.0.1"),
        ("2001:0DB8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
        ("2001:0:0:1:0:0:1:1", "2001::1:0:0:1:1"),
        ("1:0:2:3:4:5:6:7", "1:0:2:3:4:5:6:7"),
        ("::", "::"), ("::1", "::1"), ("2001:db8::", "2001:db8::"),
        ("::FFFF:192.0.2.1", "192.0.2.1"), ("::ffff:c000:201", "192.0.2.1"),
        ("::192.0.2.1", "::c000:201"), ("1:2:3:4:5:6:192.0.2.1", "1:2:3:4:5:6:c000:201"),
        ("1:2:3:4:5::192.0.2.1", "1:2:3:4:5:0:c000:201"),
        ("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
    ]:
        good(text, "ip", canonical)
    for text, canonical in [
        ("AS13335", "AS13335"), ("as0013335", "AS13335"), ("13335", "AS13335"),
        ("\r\n AS1 \f", "AS1"), ("AS23455", "AS23455"), ("23457", "AS23457"),
        ("64495", "AS64495"), ("131072", "AS131072"), ("4199999999", "AS4199999999"),
        ("AS" + "0" * 125 + "1", "AS1"),
    ]:
        good(text, "asn", canonical)
    for text in [
        "", " \t\n", "01.2.3.4", "1.2.3", "1.2.3.256", "1.2.3.4.", "0x1.2.3.4",
        "1.2.3.04", "[2001:db8::1]", "fe80::1%eth0", "::1%25eth0", "2001:db8::1/64",
        "2001:db8:::1", "2001::db8::1", "1:2:3:4:5:6:7", "1:2:3:4:5:6:7:8:9",
        "1:2:3:4:5:6:7::8", "::192.0.2.01", "192.0.2.1::", "1:2:3:4:5:6:7:192.0.2.1",
        "https://1.1.1.1", "example.test", "AS0", "AS23456", "AS64496", "AS64511",
        "AS64512", "AS65534", "AS65535", "AS65536", "AS65551", "AS65552", "AS131071",
        "AS4200000000", "AS4294967294", "AS4294967295", "4294967296", "99999999999999999999999",
        "AS", "AS-1", "+13335", "AS 13335", "1.1. 1.1", "\u00a01.1.1.1", "1.1.1.1\u2003",
        "AS١٣٣٣٥", "1.1.1.1\x00", "AS" + "0" * 126 + "1", "1" * 129,
    ]:
        bad(text)
    urls = []
    def url(route, raw, expected):
        urls.append({"route": route, "raw": raw, "expected": expected})
    def ok(route, raw, q, kind, state="ok", destination=None, origin=None):
        expected = {"state": state, "route": destination or route, "q": q, "kind": kind}
        if origin is not None:
            expected["origin"] = origin
        expected["query"] = "q=" + quote(q, safe="")
        if origin is not None:
            expected["query"] += "&origin=" + quote(origin, safe="")
        url(route, raw, expected)
    url("/ip", "", {"state": "hero", "route": "/ip"})
    url("/ip/overview", "", {"state": "redirect", "route": "/ip"})
    ok("/ip", "q=1.1.1.1", "1.1.1.1", "ip", "redirect", "/ip/overview")
    ok("/ip", "q=as0013335", "AS13335", "asn", "redirect", "/ip/asn")
    ok("/ip/overview", "q=2001%3A0DB8%3A%3A1", "2001:db8::1", "ip")
    ok("/ip/quality", "q=AS13335", "AS13335", "asn", "redirect", "/ip/asn")
    ok("/ip/class-c", "q=%3A%3A1", "::1", "ip")
    ok("/ip/asn", "q=1.1.1.1", "1.1.1.1", "ip")
    ok("/ip/bgp", "origin=as0013335&q=%3A%3Affff%3A1.1.1.1", "1.1.1.1", "ip", origin="AS13335")
    ok("/ip/bgp", "q=13335", "AS13335", "asn")
    ok("/ip/overview", "q=+1.1.1.1+", "1.1.1.1", "ip")
    ok("/ip/overview", "%71=1.1.1.1", "1.1.1.1", "ip")
    for raw in [
        "q=", "q", "q=1.1.1.1&q=8.8.8.8", "q=1.1.1.1&%71=8.8.8.8",
        "q=1.1.1.1&origin=AS1&origin=AS1", "q=1.1.1.1&", "&q=1.1.1.1", "q=1.1.1.1&&",
        "q=1.1.1.1&extra=1", "=1.1.1.1", "Q=1.1.1.1", "origin=AS13335",
        "q=%", "q=%0", "q=%GG", "q=%FF", "q=%C0%AF", "q=%ED%A0%80", "q=1.1.1.1&origin=",
        "q=" + "1" * 1023,
    ]:
        url("/ip/bgp", raw, {"state": "error", "error": "invalid_query"})
    for raw in ["q=%20", "q=example.test", "q=1.1.1.1%2F24", "q=AS64512", "q=%251.1.1.1", "q=1.1.1.1%3Borigin%3DAS1"]:
        url("/ip/bgp", raw, {"state": "error", "error": "invalid_input"})
    for route, raw in [
        ("/ip/overview", "q=1.1.1.1&origin=AS13335"),
        ("/ip/bgp", "q=AS13335&origin=AS13335"),
        ("/ip/bgp", "q=1.1.1.1&origin=8.8.8.8"),
        ("/ip/bgp", "q=1.1.1.1&origin=AS64512"),
    ]:
        url(route, raw, {"state": "error", "error": "invalid_origin"})
    url("/latency", "q=1.1.1.1", {"state": "error", "error": "invalid_route"})
    put("queries.json", {"contract_revision": 1, "synthetic": True, "inputs": inputs, "urls": urls,
                         "origin_membership": [{"requested": 13335, "origins": [13335, 15169], "valid": True},
                                               {"requested": 15169, "origins": [13335, 15169], "valid": True},
                                               {"requested": 1, "origins": [13335, 15169], "valid": False},
                                               {"requested": 13335, "origins": [], "valid": False}]})


def layouts():
    names = ["router", "geo", "coordinates", "network", "usage", "quality", "subnet24", "asn", "rpki", "bgp_origins", "bgp_paths", "bgp_relationships", "tier1", "dictionary"]
    widths = [16, 24, 16, 40, 8, 32, 24, 64, 16, 16, 24, 16, 16, 0]
    sections = [[1, 2, 3, 4, 7], [1, 3, 7, 8], [1, 3, 8], [1, 3, 4, 7, 8], [1, 3, 8], [1, 3, 8], [1, 3, 7, 10], [2, 3, 7, 11, 12], [1, 3, 8], [1, 3, 4, 8], [2, 3, 4, 9], [2, 3, 4], [2, 3], [5, 6]]
    pres_names = ["physical_country", "registration_country", "region", "city", "coordinates", "usage_type", "assignment_mode", "anycast", "ipv4_directed_broadcast", "quality", "exact_contribution", "prefix_contribution", "asn_contribution", "neighbor_contribution", "reason_flags", "network", "as_name", "organization", "isp", "origins", "rpki_status", "ipv4_24_profile", "aggregate_quality", "asn_risk", "prefix_pages", "customer_cone", "transit_degree", "network_class", "stability", "bgp_paths", "as_relationships", "asn_country"]
    reason_names = ["malware", "botnet", "command_control", "abuse", "fraud", "scanning", "spam", "tor", "vpn", "proxy", "datacenter", "hosting", "asn_context", "subnet_context"]
    def mask(*bits):
        return sum(1 << bit for bit in bits)
    # Explicit source-free boundary facts, not code-produced lookup answers.
    rows = [
        struct.pack("<IHHQ", 0, 1, 0, 0),
        struct.pack("<IHHIIII", mask(0, 1, 2, 3), 66, 539, 0, 0, 0, 1),
        struct.pack("<IiiB3x", mask(4), 0, 0, 3),
        struct.pack("<IIIIIIIIII", mask(15, 16, 17, 18, 19), 0, 2, 0, 0, 0, 0, 1, 0, 2),
        struct.pack("<IBBBB", mask(5, 6, 7, 8), 1, 1, 0, 0),
        struct.pack("<IIBBBBIIIII", mask(9, 10, 11, 12, 13, 14), mask(*range(14)), 1, 0, 3, 0, 550000, 180000, 150000, 120000, 0),
        struct.pack("<IIHHHHIBBH", mask(21), 0, 1, 1, 1, 0, 13335, 0, 0, 0),
        struct.pack("<IIIIIIHBBIIIIIIBB10x", mask(14, 16, 17, 23, 24, 25, 26, 27, 28, 31), 13335, 0, 0, 0, 1, 539, 2, 2, 500000, 1 << 12, 0, 1, 10, 2, 2, 2),
        struct.pack("<IIBB6x", mask(20), 13335, 1, 24),
        struct.pack("<IIII", mask(19), 0, 2, 0),
        struct.pack("<IIIHBBQ", mask(29), 13335, 0, 1, 1, 2, 0),
        struct.pack("<IIIBBH", mask(30), 13335, 15169, 1, 3, 0),
        struct.pack("<IIBB6x", mask(27, 28), 13335, 1, 2),
    ]
    field_specs = [
        [("destinations_first", 4), ("destinations_count", 2), ("reserved", 10)],
        [("presence", 4), ("physical_country", 2), ("registration_country", 2), ("region", 8), ("city", 8)],
        [("presence", 4), ("latitude", 4), ("longitude", 4), ("precision", 1), ("reserved", 3)],
        [("presence", 4), ("origins_first", 4), ("origins_count", 4), ("reserved", 4), ("as_name", 8), ("organization", 8), ("isp", 8)],
        [("presence", 4), ("usage_type", 1), ("assignment_mode", 1), ("bools", 1), ("reserved", 1)],
        [("presence", 4), ("reason_flags", 4), ("status", 1), ("score", 1), ("confidence", 1), ("reserved", 1), ("exact_contribution", 4), ("prefix_contribution", 4), ("asn_contribution", 4), ("neighbor_contribution", 4), ("reserved", 4)],
        [("presence", 4), ("cells_first", 4), ("cells_count", 2), ("assessed_count", 2), ("positive_count", 2), ("reserved", 2), ("dominant_asn", 4), ("aggregate_score", 1), ("confidence", 1), ("reserved", 2)],
        [("presence", 4), ("asn", 4), ("as_name", 8), ("organization", 8), ("country", 2), ("risk_band", 1), ("confidence", 1), ("risk", 4), ("reason_flags", 4), ("prefix_pages_first", 4), ("prefix_pages_count", 4), ("customer_cone", 4), ("transit_degree", 4), ("network_class", 1), ("stability", 1), ("reserved", 10)],
        [("presence", 4), ("origin_asn", 4), ("status", 1), ("maximum_length", 1), ("reserved", 6)],
        [("presence", 4), ("origins_first", 4), ("origins_count", 4), ("reserved", 4)],
        [("presence", 4), ("origin_asn", 4), ("segments_first", 4), ("segments_count", 2), ("flags", 1), ("visibility_band", 1), ("reserved", 8)],
        [("presence", 4), ("from_asn", 4), ("to_asn", 4), ("relation", 1), ("flags", 1), ("reserved", 2)],
        [("presence", 4), ("asn", 4), ("network_class", 1), ("stability", 1), ("reserved", 6)], []]
    shards = []
    for index, (name, width, required) in enumerate(zip(names, widths, sections)):
        fields, offset = [], 0
        for field, size in field_specs[index]:
            fields.append({"name": field, "offset": offset, "bytes": size})
            offset += size
        assert offset == width
        shard = {"id": index + 1, "name": name, "sections": required, "record_bytes": width, "fields": fields}
        if width:
            assert len(rows[index]) == width, (name, len(rows[index]), width)
            shard["record_hex"] = rows[index].hex()
            shard["section3_hex"] = (struct.pack("<II", 1, width) + rows[index]).hex()
        shards.append(shard)
    import ipaddress
    keys = []
    for addr, bits, flags in [("1.1.1.0", 24, 0), ("1.1.1.1", 32, 1), ("2001:db8::", 32, 0), ("2001:db8::1", 128, 1)]:
        ip = ipaddress.ip_address(addr)
        encoded = ip.packed if ip.version == 6 else b"\0" * 12 + ip.packed
        keys.append({"address": addr, "bits": bits, "flags": flags, "hex": struct.pack("<BBH", ip.version, bits, flags).hex() + encoded.hex() + struct.pack("<IQ", 0, 0).hex()})
    cell = struct.pack("<BBBBIBBHIIIB7x", 1, 0xff, 1, 1, 1, 0, 3, 0, 1000000, 0, 0, 0)
    assert len(cell) == 32
    put("via3-layouts.json", {
        "format_version": 3, "schema_version": 3, "contract_revision": 1, "synthetic": True,
        "max_file_exclusive": 24 * 1024 * 1024, "max_decoded_section": 64 * 1024 * 1024,
        "max_decoded_total": 256 * 1024 * 1024, "max_window": 8 * 1024 * 1024,
        "presence_bits": dict(zip(pres_names, range(32))), "reason_bits": dict(zip(reason_names, range(14))),
        "shards": shards, "prefix_keys": keys, "cell_hex": cell.hex(),
        "dictionary": {"strings": ["Example City", "Example Region", "Example Transit"],
                       "offsets": [0, 12, 26, 41], "utf8_hex": b"Example CityExample RegionExample Transit".hex()},
        "required_corruption_vectors": ["short_header", "exactly_24_mib", "u64_overflow", "bad_magic", "unknown_format", "unknown_schema", "reserved_header", "unknown_codec", "duplicate_section", "unknown_section", "missing_section", "overlap", "gap", "trailing_bytes", "truncation", "decoded_length_mismatch", "checksum_mismatch", "window_limit", "output_limit", "bad_dictionary_id", "unsorted_index", "bad_prefix_host_bits", "bad_origin_order", "partial_null_reference", "withdrawn_overlay"],
    })


if __name__ == "__main__":
    queries()
    layouts()
