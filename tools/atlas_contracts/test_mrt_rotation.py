import copy
import json
import unittest

from jsonschema import Draft202012Validator

from tools.atlas_contracts.config import ContractError, ROOT, validate_mrt_archive_policy


class MRTArchiveRotationContractTests(unittest.TestCase):
    def source(self):
        url = "https://data.ris.ripe.net/rrc18/2026.11/bview.20261115.0800.gz"
        return {"category": "bgp", "scope": "path",
                "download": {"url": url, "format": "mrt-gz", "max_compressed_mib": 128,
                             "mrt_archive_policy": "latest-complete-v1"},
                "parser": {"id": "mrt-table-dump-v2", "schema": "mrt-table-dump-v2-unicast-v1", "version": 1},
                "publication_proof": {"kind": "embedded", "locator": url, "field": "mrt_frame_capture_timestamp"}}

    def test_closed_download_policy_and_no_implicit_activation(self):
        source = self.source()
        schema = json.loads((ROOT / "schemas/sources.schema.json").read_text())
        validator = Draft202012Validator(schema["properties"]["sources"]["items"]["properties"]["download"])
        self.assertFalse(list(validator.iter_errors(source["download"])))
        validate_mrt_archive_policy(source)
        for value in [None, "", "latest", True, {"latest": True}]:
            bad = copy.deepcopy(source)
            bad["download"]["mrt_archive_policy"] = value
            self.assertTrue(list(validator.iter_errors(bad["download"])))
            with self.assertRaises(ContractError):
                validate_mrt_archive_policy(bad)
        del source["download"]["mrt_archive_policy"]
        source["download"]["url"] = "https://example.com/fixed.mrt"
        validate_mrt_archive_policy(source)

    def test_collector_codec_calendar_and_proof_are_closed(self):
        for url, codec in [
            ("https://archive.routeviews.org/route-views.wide/bgpdata/2026.11/RIBS/rib.20261115.1200.bz2", "mrt-bz2"),
            (self.source()["download"]["url"], "mrt-gz"),
        ]:
            source = self.source()
            source["download"].update(url=url, format=codec)
            source["publication_proof"]["locator"] = url
            validate_mrt_archive_policy(source)
            for bad_url in [url + "?x=1", url + "#fragment", url.replace("https://", "http://"),
                            url.replace("20261115", "20261131"), url.replace("2026.11", "2026.10"),
                            url.replace("rrc18", "rrc00").replace("route-views.wide", "route-views3"),
                            url.replace(".0800.", ".0801.").replace(".1200.", ".1201.")]:
                bad = copy.deepcopy(source)
                bad["download"]["url"] = bad_url
                bad["publication_proof"]["locator"] = bad_url
                with self.assertRaises(ContractError):
                    validate_mrt_archive_policy(bad)
            for section, key, value in [("download", "format", "json"), ("parser", "id", "mrt-bgp4mp"),
                                        ("publication_proof", "locator", "https://example.com/other")]:
                bad = copy.deepcopy(source)
                bad[section][key] = value
                with self.assertRaises(ContractError):
                    validate_mrt_archive_policy(bad)


if __name__ == "__main__":
    unittest.main()
