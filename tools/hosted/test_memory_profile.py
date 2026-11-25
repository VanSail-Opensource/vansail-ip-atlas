import base64
from copy import deepcopy
import json
from pathlib import Path
import struct
import unittest

from tools.hosted.memory_profile import BUDGETS, _verify_observation, inspect_object
from tools.release_contract.contracts import ContractError

ROOT = Path(__file__).resolve().parents[2]


class MemoryProfileTests(unittest.TestCase):
    def fixture(self):
        objects = {str(kind): {"kind": kind, "decoded_bytes": 32 << 20 if kind in (1, 2, 5) else 1024}
                   for kind in (1, 2, 4, 5, 8, 11, 13, 14)}
        cases = [
            {"name": "maximum-materialized-answer", "q": "203.0.113.1", "action": "lookup", "answer_bytes": 8 << 20,
             "retain_answer": True, "required_objects": ["1", "4", "8", "11", "13", "14"]},
            {"name": "maximum-live-decoded", "q": "203.0.113.250", "action": "lookup", "answer_bytes": 486,
             "required_objects": ["1", "2", "5"]},
            {"name": "live-limit-rejection", "q": "203.0.113.2", "action": "lookup", "expected_error": "resource_limit",
             "required_objects": ["1", "2", "4"]}]
        observed = {"completed_cases": 3, "errors": [], "object_hashes": list(objects), "retained_answer_bytes": [8 << 20],
                    "cases": [{"name": case["name"], "answer_bytes": case.get("answer_bytes", 0),
                               "repeat_answer_bytes": case.get("answer_bytes", 0), "retained_answers": 1} for case in cases]}
        return {"cases": cases}, observed, objects

    def test_observations_must_prove_every_boundary_and_retention(self):
        profile, observed, objects = self.fixture()
        _verify_observation(profile, observed, objects)
        mutations = [lambda value: value["cases"][0].update(answer_bytes=(8 << 20) - 1),
                     lambda value: value["cases"][1].update(repeat_answer_bytes=0),
                     lambda value: value["cases"].reverse(),
                     lambda value: value["cases"][2].update(retained_answers=0),
                     lambda value: value.update(retained_answer_bytes=[]),
                     lambda value: value["object_hashes"].remove("2")]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                changed = deepcopy(observed)
                mutate(changed)
                with self.assertRaises(ContractError):
                    _verify_observation(profile, changed, objects)
        objects["5"]["decoded_bytes"] -= 8
        with self.assertRaises(ContractError):
            _verify_observation(profile, observed, objects)

    def test_actual_go_golden_frames_and_corrupt_envelopes(self):
        fixture = json.loads((ROOT / "fixtures/bin/synthetic-via3.json").read_bytes())
        objects = [obj for obj in fixture["objects"] if obj["info"]["kind"] in (1, 2, 4, 5, 8, 11, 13, 14)]
        self.assertEqual({obj["info"]["kind"] for obj in objects}, {1, 2, 4, 5, 8, 11, 13, 14})
        for obj in objects:
            data = base64.b64decode(obj["base64"])
            metric = inspect_object(data)
            self.assertEqual(metric["sha256"], obj["info"]["sha256"])
            self.assertEqual(metric["decoded_bytes"], struct.unpack_from("<Q", data, 36)[0])
            self.assertLessEqual(metric["decoder_window_bytes"], BUDGETS["decoder_window_bytes"])
        data = base64.b64decode(objects[0]["base64"])
        for offset, value in ((4, 2), (6, 3), (6, 4), (6, 6), (36, 1), (44, 0), (64 + 2, 0)):
            changed = bytearray(data)
            changed[offset] = value
            with self.subTest(offset=offset), self.assertRaises(ContractError):
                inspect_object(bytes(changed))
        with self.assertRaises(ContractError):
            inspect_object(data + b"trailing")


if __name__ == "__main__":
    unittest.main()
