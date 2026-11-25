import io
import tarfile
from pathlib import Path
import tempfile
import os
import shutil
import subprocess
import unittest
from unittest.mock import patch

from tools.hosted.checkpoint import REPOSITORY, WORKFLOWS, extract_authenticated, member_name, validate_envelope, pack, unpack
from tools.release_contract.contracts import ContractError

class CheckpointTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('age') and shutil.which('age-keygen'),'pinned age CLI required for crypto roundtrip')
    def test_real_age_roundtrip_wrong_key_and_ciphertext_corruption(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);identity=root/'key'
            subprocess.run(['age-keygen','-o',str(identity)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True)
            recipient=subprocess.check_output(['age-keygen','-y',str(identity)],text=True).strip()
            source=root/'source';(source/'.atlas-private').mkdir(parents=True)
            (source/'.atlas-private/state-v1.json').write_bytes(b'{"Sources":[]}')
            (source/'.atlas-private/state-seal.key').write_bytes(b'x'*32)
            (source/'.atlas-private/production-build.json').write_bytes(b'{"scope":"hosted-production-build-v2"}')
            environment={'GITHUB_REPOSITORY':REPOSITORY,'GITHUB_REF':'refs/heads/main','GITHUB_SHA':'a'*40,
                'GITHUB_RUN_ID':'1','GITHUB_RUN_ATTEMPT':'1','ATLAS_STATE_AGE_RECIPIENT':recipient,
                'ATLAS_STATE_AGE_IDENTITY':identity.read_text()}
            run={'status':'completed','conclusion':'success','path':WORKFLOWS['benchmark'],'head_branch':'main',
                'head_repository':{'full_name':REPOSITORY},'event':'schedule','id':1,'run_attempt':1,'head_sha':'a'*40}
            with patch.dict(os.environ,environment):
                pack(source,root/'encrypted','benchmark',100)
                restored=root/'restored';restored.mkdir()
                unpack(root/'encrypted',restored,run,101)
                self.assertEqual((restored/'.atlas-private/state-seal.key').read_bytes(),b'x'*32)
                self.assertEqual((restored/'.atlas-private/production-build.json').read_bytes(),b'{"scope":"hosted-production-build-v2"}')
                wrong=root/'wrong';wrong.mkdir()
                with patch.dict(os.environ,{'ATLAS_STATE_AGE_IDENTITY':'invalid'}),self.assertRaises(ContractError):
                    unpack(root/'encrypted',wrong,run,101)
                cipher=root/'encrypted/checkpoint.tar.gz.age';cipher.write_bytes(cipher.read_bytes()[:-1])
                with self.assertRaises(ContractError):unpack(root/'encrypted',wrong,run,101)

    def test_envelope_expiry_and_producer_binding_have_closed_fields(self):
        value={'format_version':1,'kind':'intake','repository':REPOSITORY,'head_sha':'a'*40,
            'run_id':1,'run_attempt':1,'created_at':100,'expires_at':200,
            'ciphertext_sha256':'b'*64,'ciphertext_bytes':10,'key_id':'c'*16}
        self.assertEqual(validate_envelope(value,150),value)
        for change in ({'expires_at':150},{'created_at':151},{'run_id':True},{'repository':'attacker/fork'},
                       {'source_id':'private'},{'ciphertext_bytes':9*1024**3}):
            with self.subTest(change=change),self.assertRaises(ContractError):
                validate_envelope({**value,**change},150)

    def test_raw_subscriptions_scratch_keys_and_paths_outside_allowlist_fail(self):
        for name in ('../state-v1.json','/.atlas-private/state-v1.json','.atlas-private/intake-abc/body',
                     '.atlas-private/admission-engine-v1.lock','.atlas-private/quarantine/input',
                     '.atlas-private/records-v2/../secret','configs/sources.yaml','.atlas-private/stage.log'):
            with self.subTest(name=name),self.assertRaises(ContractError):member_name(name)
        self.assertEqual(member_name('.atlas-private/state-seal-v2.json'),'.atlas-private/state-seal-v2.json')
        self.assertEqual(member_name('.atlas-private/records-v2/abc'),'.atlas-private/records-v2/abc')
        self.assertEqual(member_name('.atlas-private/production-build.json'),'.atlas-private/production-build.json')
        self.assertEqual(WORKFLOWS['benchmark'],'.github/workflows/production-benchmark-join.yml')

    def archive(self,members):
        stream=io.BytesIO()
        with tarfile.open(fileobj=stream,mode='w') as archive:
            for name,kind in members:
                entry=tarfile.TarInfo(name);entry.type=kind
                entry.size=2 if kind==tarfile.REGTYPE else 0
                archive.addfile(entry,io.BytesIO(b'{}') if entry.size else None)
        stream.seek(0);return stream

    def test_only_regular_unique_state_files_can_be_restored(self):
        good=[('.atlas-private/state-v1.json',tarfile.REGTYPE)]
        with tempfile.TemporaryDirectory() as directory:
            extract_authenticated(self.archive(good),Path(directory))
            self.assertEqual((Path(directory)/'.atlas-private/state-v1.json').read_bytes(),b'{}')
        for members in (good*2,[('.atlas-private/state-v1.json',tarfile.SYMTYPE)],
                        [('../outside',tarfile.REGTYPE)],[('.atlas-private/production-receipt.json',tarfile.REGTYPE)]):
            with self.subTest(members=members),tempfile.TemporaryDirectory() as directory,self.assertRaises(ContractError):
                extract_authenticated(self.archive(members),Path(directory))

if __name__=='__main__':unittest.main()
