import base64
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.hosted import test_candidate as candidate_fixture
from tools.release_contract.contracts import ContractError
from tools.release_contract.pages import NoRedirect, Pages


class PagesReleaseTests(unittest.TestCase):
    def client(self):
        return Pages("a" * 32, "atlas", "credential-for-unit-fixture-only")

    def test_asset_upload_is_bounded_hash_verified_and_control_files_are_separate(self):
        with tempfile.TemporaryDirectory() as directory:
            public = Path(directory)
            files, candidate = candidate_fixture.CandidateTests().fixture(public, "production")
            client, uploaded, calls = self.client(), [], []
            def request(path, **kwargs):
                calls.append((path, kwargs))
                if path.endswith('/upload-token'):
                    return {"jwt": "ephemeral-fixture-token-not-written"}
                if path.endswith('/check-missing'):
                    return kwargs['value']['hashes']
                if path.endswith('/upload'):
                    uploaded.extend(kwargs['value'])
                return None
            with patch.object(client, "request", side_effect=request), patch('tools.release_contract.pages.time.time', return_value=150):
                manifest = client.upload_assets(public, candidate)
            self.assertEqual(set(manifest), {'/' + name for name in files if name not in ('_headers', '_redirects')})
            by_key = {item['key']: item for item in uploaded}
            for name, key in manifest.items():
                content = base64.b64decode(by_key[key]['value'])
                self.assertEqual(content, files[name[1:]])
                self.assertEqual(key, hashlib.sha256(content + Path(name).suffix.encode()).hexdigest()[:32])
            self.assertTrue(all(call[1].get('asset_token') == 'ephemeral-fixture-token-not-written'
                                for call in calls if call[0].startswith('/pages/assets/')))

    def test_create_keeps_control_bytes_separate_and_records_exact_bundle_revision(self):
        with tempfile.TemporaryDirectory() as directory:
            public = Path(directory)
            files, candidate = candidate_fixture.CandidateTests().fixture(public, "production")
            candidate['valid_until'] = 200
            client = self.client()
            deployment_id = '12345678-1234-1234-1234-123456789abc'
            with patch.object(client, 'request', return_value={'id':deployment_id}) as request, patch.object(client, 'wait', return_value={'id':deployment_id}):
                client.create(public, candidate, {'/ip/index.html':'a'*32}, 'main', 'b'*40)
            kwargs = request.call_args.kwargs
            self.assertEqual(kwargs['method'], 'POST')
            body = kwargs['body']
            self.assertIn(files['_headers'], body)
            self.assertIn(files['_redirects'], body)
            self.assertIn(('atlas:' + candidate['candidate_bundle_sha256']).encode(), body)
            self.assertIn(b'b'*40, body)
            self.assertNotIn(b'credential-for-unit-fixture-only', body)
            self.assertNotIn(b'_worker.js', body)
            self.assertEqual(client.created_deployment_id, deployment_id)

    def test_credentials_cannot_be_redirected_or_sent_to_an_arbitrary_route(self):
        self.assertIsNone(NoRedirect().redirect_request(None, None, None, None, None, None))
        client = self.client()
        for route in ('https://other.invalid', '/accounts/other/pages/projects/atlas', client.prefix+'/../tokens'):
            with self.subTest(route=route), self.assertRaises(ContractError):
                client.request(route)
        for account, project, token in (('bad','atlas','a'*30), ('a'*32,'../atlas','a'*30), ('a'*32,'atlas','a'*30+'\n')):
            with self.assertRaises(ContractError):
                Pages(account,project,token)


if __name__ == '__main__':
    unittest.main()
