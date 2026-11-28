import base64
import contextlib
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import socket
import ssl
import sys
import tempfile
import unittest
import urllib.error
from unittest.mock import patch

from tools.hosted import test_candidate as candidate_fixture
from tools.release_contract.contracts import ContractError
from tools.release_contract import pages
from tools.release_contract.pages import MAX_ASSET_ATTEMPTS, NoRedirect, Pages, PagesRequestFailure, _retry_delay


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
            self.assertEqual([path.rsplit('/', 1)[-1] for path, _ in calls],
                             ['upload-token', 'check-missing', 'upload', 'upsert-hashes'])

    def test_upsert_400_rechecks_all_keys_with_a_fresh_token_after_partial_refresh(self):
        with tempfile.TemporaryDirectory() as directory:
            public = Path(directory)
            files, candidate = candidate_fixture.CandidateTests().fixture(public, "production")
            client = self.client()
            first, second = 'unit-only-first-asset-token', 'unit-only-second-asset-token'
            manifest = {f'/{path}': hashlib.sha256(data + Path(path).suffix.encode()).hexdigest()[:32]
                        for path, data in files.items() if path not in ('_headers', '_redirects')}
            hashes = sorted(set(manifest.values()))
            batches = [hashes[index:index + 2] for index in range(0, len(hashes), 2)]
            self.assertGreater(len(batches), 2)
            calls = []

            def request(path, **kwargs):
                route = path.rsplit('/', 1)[-1]
                token = kwargs.get('asset_token')
                if route == 'upload-token':
                    refresh = bool(calls)
                    calls.append((route, token, None))
                    return {'jwt': second if refresh else first}
                if route == 'check-missing':
                    requested = kwargs['value']['hashes']
                    calls.append((route, token, requested))
                    return [hashes[0]] if token == first and hashes[0] in requested else []
                if route == 'upload':
                    uploaded = [item['key'] for item in kwargs['value']]
                    calls.append((route, token, uploaded))
                    return None
                if route == 'upsert-hashes':
                    requested = kwargs['value']['hashes']
                    calls.append((route, token, requested))
                    if requested == batches[1]:
                        raise PagesRequestFailure('http-400')
                    return None
                self.fail('unexpected route')

            log = io.StringIO()
            with (patch.object(client, 'request', side_effect=request),
                  patch.object(pages, 'ASSET_HASH_BATCH', 2),
                  patch.object(pages.time, 'time', return_value=150),
                  patch.object(pages, 'check_candidate', wraps=pages.check_candidate) as local,
                  contextlib.redirect_stderr(log)):
                self.assertEqual(client.upload_assets(public, candidate), manifest)
            self.assertEqual(calls, [('upload-token', None, None),
                                    *(('check-missing', first, batch) for batch in batches),
                                    ('upload', first, [hashes[0]]),
                                    *(('upsert-hashes', first, batch) for batch in batches[:2]),
                                    ('upload-token', None, None),
                                    *(('check-missing', second, batch) for batch in batches)])
            self.assertEqual(log.getvalue(), 'Pages advisory asset hash refresh was rejected. All staged asset keys were confirmed present.\n')
            self.assertEqual(local.call_count, 2)
            self.assertEqual(client.progress.phase, 'asset-final-check')

    def test_upsert_400_never_accepts_missing_malformed_or_failed_presence_proof(self):
        with tempfile.TemporaryDirectory() as directory:
            public = Path(directory)
            _, candidate = candidate_fixture.CandidateTests().fixture(public, "production")
            first, second = 'unit-only-first-asset-token', 'unit-only-second-asset-token'
            for reply in ('missing', 'map', 'foreign-key', 'duplicate', 'invalid-item', 'http-400', 'invalid-token'):
                with self.subTest(reply=reply):
                    client = self.client()
                    stages, log = [], io.StringIO()

                    def request(path, **kwargs):
                        route = path.rsplit('/', 1)[-1]
                        stages.append(route)
                        if route == 'upload-token':
                            if stages.count(route) == 1:
                                return {'jwt': first}
                            return {'jwt': second} if reply != 'invalid-token' else {'jwt': []}
                        if route == 'upsert-hashes':
                            raise PagesRequestFailure('http-400')
                        if route == 'check-missing':
                            if kwargs['asset_token'] == first:
                                return []
                            requested = kwargs['value']['hashes']
                            if reply == 'http-400':
                                raise PagesRequestFailure('http-400')
                            return {'missing': [requested[0]], 'map': {'hashes': []}, 'foreign-key': ['0' * 32],
                                    'duplicate': [requested[0]] * 2, 'invalid-item': [False]}[reply]
                        self.fail('unexpected route')

                    with (patch.object(client, 'request', side_effect=request),
                          patch.object(pages.time, 'time', return_value=150),
                          patch.object(pages, 'check_candidate', wraps=pages.check_candidate) as local,
                          contextlib.redirect_stderr(log), self.assertRaises(ContractError) as rejected):
                        client.upload_assets(public, candidate)
                    self.assertEqual(stages[:4], ['upload-token', 'check-missing', 'upsert-hashes', 'upload-token'])
                    self.assertEqual(len(stages), 4 if reply == 'invalid-token' else 5)
                    self.assertEqual(client.progress.phase, 'asset-token' if reply == 'invalid-token' else 'asset-check')
                    if reply == 'http-400':
                        self.assertIsInstance(rejected.exception, PagesRequestFailure)
                        self.assertEqual(rejected.exception.classification, 'http-400')
                    self.assertEqual(log.getvalue(), '')
                    local.assert_called_once()

    def test_only_advisory_upsert_http_400_can_request_a_presence_recheck(self):
        with tempfile.TemporaryDirectory() as directory:
            public = Path(directory)
            _, candidate = candidate_fixture.CandidateTests().fixture(public, "production")
            for failed_route, code in (('upload', 'http-400'), ('check-missing', 'http-400'),
                                       ('upsert-hashes', 'http-401'), ('upsert-hashes', 'http-403'),
                                       ('upsert-hashes', 'http-503'), ('upsert-hashes', 'response')):
                with self.subTest(route=failed_route, code=code):
                    client = self.client()
                    stages, log = [], io.StringIO()

                    def request(path, **kwargs):
                        route = path.rsplit('/', 1)[-1]
                        stages.append(route)
                        if route == failed_route:
                            raise PagesRequestFailure(code)
                        if route == 'upload-token':
                            return {'jwt': 'unit-only-first-asset-token'}
                        if route == 'check-missing':
                            return kwargs['value']['hashes'] if failed_route == 'upload' else []
                        self.fail('unexpected route')

                    with (patch.object(client, 'request', side_effect=request),
                          patch.object(pages.time, 'time', return_value=150),
                          contextlib.redirect_stderr(log), self.assertRaises(PagesRequestFailure) as rejected):
                        client.upload_assets(public, candidate)
                    self.assertEqual(rejected.exception.classification, code)
                    self.assertEqual(stages.count('upload-token'), 1)
                    self.assertEqual(stages[-1], failed_route)
                    self.assertEqual(log.getvalue(), '')

    def test_batch_limits_include_both_decoded_bytes_and_number_of_assets(self):
        with tempfile.TemporaryDirectory() as directory:
            public = Path(directory)
            entries = []
            for index in range(5):
                name, data = f"{index}.txt", f"id{index}".encode()
                (public / name).write_bytes(data)
                entries.append((name, len(data), hashlib.sha256(data).hexdigest()))
            client = self.client()
            for max_files, max_bytes, expected_sizes in ((2, 100, [2, 2, 1]), (100, 6, [2, 2, 1])):
                with self.subTest(max_files=max_files, max_bytes=max_bytes):
                    sizes = []
                    def request(path, **kwargs):
                        if path.endswith("/upload-token"):
                            return {"jwt": "ephemeral-fixture-token-not-written"}
                        if path.endswith("/check-missing"):
                            return kwargs["value"]["hashes"]
                        if path.endswith("/upload"):
                            sizes.append(len(kwargs["value"]))
                    with (patch.object(client, "request", side_effect=request),
                          patch("tools.release_contract.pages.check_candidate", return_value={"entries": entries}),
                          patch("tools.release_contract.pages.UPLOAD_BUCKET_BYTES", max_bytes),
                          patch("tools.release_contract.pages.UPLOAD_BUCKET_FILES", max_files)):
                        self.assertEqual(len(client.upload_assets(public, {})), len(entries))
                    self.assertEqual(sizes, expected_sizes)

    def test_retry_after_honors_bounded_delay_seconds_and_http_dates(self):
        with patch("tools.release_contract.pages.time.time", return_value=1000):
            self.assertEqual(_retry_delay("Thu, 01 Jan 1970 00:16:49 GMT", 2), 9)
            self.assertEqual(_retry_delay("Thu, 01 Jan 1970 00:16:30 GMT", 2), 2)
            self.assertIsNone(_retry_delay("Thu, 01 Jan 1970 00:20:00 GMT", 2))
            self.assertIsNone(_retry_delay("malformed", 2))
            self.assertEqual(_retry_delay("12", 2), 12)

    def test_only_idempotent_asset_calls_retry_transient_failures(self):
        class Success(io.BytesIO):
            length = 0

        client = self.client()
        def http_error(code, headers=None):
            return urllib.error.HTTPError("https://api.cloudflare.com", code, "fixture", headers, None)
        for path in ("/pages/assets/check-missing", "/pages/assets/upload", "/pages/assets/upsert-hashes"):
            with self.subTest(path=path), patch("tools.release_contract.pages.time.sleep") as sleep:
                with patch.object(client._opener, "open", side_effect=[
                        http_error(429, {"Retry-After": "3"}), urllib.error.URLError(ConnectionResetError()),
                        Success(b'{"success":true,"result":[]}')]) as opening:
                    self.assertEqual(client.request(path, method="POST", value={"hashes": []}), [])
                self.assertEqual([call.args[0] for call in sleep.call_args_list], [3, 2])
                self.assertEqual(len({id(call.args[0]) for call in opening.call_args_list}), 1)

        for path, error in ((client.prefix + "/deployments", http.client.RemoteDisconnected()),
                            (client.prefix + "/deployments/fixture/rollback", http_error(503)),
                            ("/pages/assets/upload", http_error(403)),
                            ("/pages/assets/upload", http_error(429, {"Retry-After": "600"}))):
            with self.subTest(path=path), patch("tools.release_contract.pages.time.sleep") as sleep:
                with patch.object(client._opener, "open", side_effect=error) as opening, self.assertRaises(ContractError):
                    client.request(path, method="POST")
                opening.assert_called_once()
                sleep.assert_not_called()

        with (patch.object(client._opener, "open", side_effect=TimeoutError()) as opening,
              patch("tools.release_contract.pages.time.sleep") as sleep, self.assertRaises(ContractError)):
            client.request("/pages/assets/upload", method="POST", value=[])
        self.assertEqual(opening.call_count, MAX_ASSET_ATTEMPTS)
        self.assertEqual(sleep.call_count, MAX_ASSET_ATTEMPTS - 1)

    def test_api_failure_class_never_copies_wire_details(self):
        private = "not-a-real-secret-fixture"
        failures = (
            (urllib.error.HTTPError(f'https://example.invalid/{private}', 401, private,
                                    {"Location": private, "Retry-After": private}, io.BytesIO(private.encode())), "http-401"),
            (urllib.error.URLError(socket.gaierror(socket.EAI_AGAIN, private)), "network-dns"),
            (TimeoutError(private), "network-timeout"),
            (urllib.error.URLError(ssl.SSLError(private)), "network-tls"),
            (ConnectionResetError(private), "network-connection"),
            (http.client.IncompleteRead(private.encode()), "network-interrupted"),
        )
        client = self.client()
        for error, classification in failures:
            with self.subTest(classification=classification), patch.object(client._opener, "open", side_effect=error):
                with self.assertRaises(PagesRequestFailure) as context:
                    client.request(client.prefix)
                self.assertEqual(context.exception.classification, classification)
                self.assertNotIn(private, str(context.exception))
        class Response(io.BytesIO):
            length = 0
        with patch.object(client._opener, "open", return_value=Response(json.dumps({"success": False, "errors": [private]}).encode())):
            with self.assertRaises(PagesRequestFailure) as context:
                client.request(client.prefix)
            self.assertEqual(context.exception.classification, "response")
            self.assertNotIn(private, str(context.exception))

    def test_main_logs_only_closed_failure_phase_and_safe_class(self):
        private = "private-lineage-token-path-fixture"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            public = path / "public"
            report = path / "report.json"
            argv = ['pages.py', 'preview', '--public', str(public), '--report', str(report),
                    '--qualification-receipt', private, '--account', 'a'*32, '--project', 'atlas', '--head', 'b'*40]
            for phase, code in (("frontend-inspection", "contract"), ("asset-token", "http-503")):
                class Response(io.BytesIO):
                    length = 0
                project = Response(b'{"success":true,"result":{"production_branch":"main"}}')
                upstream_error = urllib.error.HTTPError(f'https://example.invalid/{private}', 503, private,
                                                        {"Location": private}, io.BytesIO(private.encode()))
                frontend_error = ContractError(private + '\nATLAS_PAGES_FAILURE deployment-create http-401')
                out, err = io.StringIO(), io.StringIO()
                with (patch.object(sys, 'argv', argv), patch.dict(os.environ, {'CLOUDFLARE_API_TOKEN': private}),
                      patch.object(pages, 'read_private', return_value=json.dumps({'mode':'production', 'candidate_bundle_sha256':'c'*64}).encode()),
                      patch.object(pages, 'check_candidate'), patch.object(pages, 'qualify_public'),
                      patch.object(pages, 'verify_atlas', return_value={'object_count': 1}), patch.object(pages, 'inspect_binary', return_value=1),
                      patch.object(pages, 'known_private_values'), patch.object(pages, 'scan_frontend',
                          side_effect=frontend_error if code == 'contract' else None),
                      patch.object(pages.urllib.request.OpenerDirector, 'open', side_effect=[project, upstream_error]) as calls,
                      contextlib.redirect_stdout(out), contextlib.redirect_stderr(err)):
                    self.assertEqual(pages.main(), 1)
                self.assertEqual(err.getvalue(), f'ATLAS_PAGES_FAILURE {phase} {code}\n')
                self.assertEqual(out.getvalue(), '')
                self.assertNotIn(private, report.read_text())
                self.assertIsNone(json.loads(report.read_text())['deployment_id'])
                self.assertEqual(calls.call_count, 0 if code == 'contract' else 2)

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
