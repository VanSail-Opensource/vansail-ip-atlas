import json
from pathlib import Path
import tempfile
import unittest

from tools.release_contract.contracts import ContractError
from tools.release_contract.nuxt_timestamps import (
    canonicalize_operational_times, normalize_build_metadata, normalize_payload,
)


class NuxtTimestampTests(unittest.TestCase):
    def test_surgical_payload_edit_preserves_fact_clocks_and_string_escaping(self):
        payload = '[{"data":1,"prerenderedAt":4},["ShallowReactive",2],{"fact":3},"\\u003cuntouched\\u003e",123456789]'
        expected = payload.replace(",123456789]", ",1794096000000]")
        self.assertEqual(normalize_payload(payload, 1794096000000), expected)
        self.assertEqual(normalize_payload(expected, 1794096000000), expected)

    def test_shared_timestamp_reference_fails_instead_of_overwriting_fact(self):
        payload = '[{"prerenderedAt":1,"fact":2},12345,{"published_at":1}]'
        with self.assertRaises(ContractError):
            normalize_payload(payload, 1794096000000)

    def test_only_known_build_metadata_timestamp_token_changes(self):
        latest = '{ "id":"stable-build", "timestamp":12345 }\r\n'
        self.assertEqual(normalize_build_metadata(latest, 1794096000000, expected_id=None),
                         latest.replace(":12345", ":1794096000000"))
        with self.assertRaises(ContractError):
            normalize_build_metadata('{"id":"stable-build","timestamp":1,"published_at":2}', 3, expected_id=None)

    def test_operational_normalization_leaves_atlas_and_unrelated_scripts_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "ip").mkdir()
            (root / "_atlas").mkdir()
            manifest = b'{"valid_from":1794096000,"valid_until":1796688000,"published_at":12345}'
            (root / "_atlas" / "manifest.json").write_bytes(manifest)
            payload = '[{"prerenderedAt":1,"data":2},12345,{"published_at":3},67890]'
            (root / "ip/_payload.json").write_bytes(payload.encode())
            html = ('<!doctype html>\r\n<script id="__NUXT_DATA__" type="application/json">' + payload + '</script>'
                    '<script>window.fact={timestamp:12345,published_at:67890};</script>\r\n'
                    '<script id="__nuxt_data__" type="application/json">[{"prerenderedAt":1},12345]</script>')
            (root / "ip/index.html").write_bytes(html.encode())
            self.assertEqual(canonicalize_operational_times(root, 1794096000), 2)
            self.assertEqual((root / "_atlas/manifest.json").read_bytes(), manifest)
            normalized = (root / "ip/index.html").read_bytes().decode()
            self.assertEqual(normalized, html.replace('},12345,', '},1794096000000,'))
            self.assertEqual(canonicalize_operational_times(root, 1794096000), 0)

    def test_same_public_release_and_code_normalize_to_identical_bytes(self):
        outputs = []
        for operational_time in (12345, 98765):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "ip").mkdir()
                (root / "_nuxt/builds/meta").mkdir(parents=True)
                (root / "ip/_payload.json").write_text(f'[{{"prerenderedAt":1}},{operational_time}]', encoding="utf-8")
                (root / "_nuxt/builds/latest.json").write_text(json.dumps({"id": "stable-build", "timestamp": operational_time}), encoding="utf-8")
                (root / "_nuxt/builds/meta/stable-build.json").write_text(json.dumps({"id": "stable-build", "timestamp": operational_time, "prerendered": ["/ip"]}), encoding="utf-8")
                canonicalize_operational_times(root, 1794096000)
                outputs.append({path.relative_to(root).as_posix(): path.read_bytes() for path in root.rglob("*") if path.is_file()})
        self.assertEqual(outputs[0], outputs[1])
