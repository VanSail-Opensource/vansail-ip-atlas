from pathlib import Path
import tempfile
import unittest

from tools.release_contract.contracts import ContractError
from tools.release_contract.data_license import NOTICE, validate_data_license_tree

class DataLicenseTests(unittest.TestCase):
    def test_exact_approved_notice_is_bundled_and_tampering_is_rejected(self):
        source=Path(__file__).resolve().parents[2]/'web/public/data-license.txt'
        self.assertEqual(source.read_bytes(),NOTICE)
        with tempfile.TemporaryDirectory() as directory:
            public=Path(directory)
            with self.assertRaises(ContractError): validate_data_license_tree(public)
            path=public/'data-license.txt';path.write_bytes(NOTICE)
            validate_data_license_tree(public)
            path.write_bytes(NOTICE.replace(b'CC BY-SA 4.0',b'All rights reserved'))
            with self.assertRaises(ContractError): validate_data_license_tree(public)
