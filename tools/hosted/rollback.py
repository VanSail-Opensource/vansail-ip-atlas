"""Restore only a still-qualified previous exact production artifact."""
from __future__ import annotations
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from tools.hosted.checkpoint import api, digest, fetch
from tools.release_contract.contracts import ContractError

def regular_path(name: str) -> str:
    if not name or name.startswith('/') or '\\' in name or ':' in name or any(p in ('','.','..') for p in name.split('/')):
        raise ContractError('unsafe rollback artifact path')
    return name

def artifact(run: int, name: str, output: Path, limit: int):
    values=api(f'actions/runs/{run}/artifacts?per_page=100')['artifacts']
    matches=[value for value in values if value.get('name')==name and value.get('expired') is False]
    if len(matches)!=1 or not 0<matches[0]['size_in_bytes']<=limit:
        raise ContractError('eligible rollback artifact unavailable')
    entry=matches[0]
    with tempfile.TemporaryDirectory(dir=output.parent,prefix='rollback-download-') as temporary:
        path=Path(temporary)/'artifact.zip';api(f"actions/artifacts/{entry['id']}/zip",output=path)
        if entry.get('digest')!='sha256:'+digest(path):raise ContractError('rollback artifact digest differs')
        total=0;seen=set()
        with zipfile.ZipFile(path) as archive:
            for member in archive.infolist():
                if member.is_dir():continue
                name=regular_path(member.filename);total+=member.file_size
                if name in seen or total>limit or stat.S_IFMT(member.external_attr>>16) not in (0,stat.S_IFREG):
                    raise ContractError('invalid rollback artifact member')
                seen.add(name);target=output/name;target.parent.mkdir(parents=True,exist_ok=True)
                with archive.open(member) as source,target.open('xb') as destination:shutil.copyfileobj(source,destination,1024*1024)

def restore() -> dict:
    failed=json.loads((ROOT/'reports/pages-deployment.json').read_bytes())
    if failed.get('operation')!='promote' or not failed.get('deployment_id'):
        raise ContractError('no known failed deployment to replace')
    with tempfile.TemporaryDirectory(prefix='rollback-',dir=ROOT/'build-private') as temporary:
        workspace=Path(temporary)
        # Current reviewed policy/code revalidates the retained original state.
        code=subprocess.check_output(['git','archive','HEAD'],cwd=ROOT)
        with tarfile.open(fileobj=io.BytesIO(code)) as archive:
            for member in archive:
                if member.isdir():continue
                name=regular_path(member.name)
                if not member.isfile():raise ContractError('rollback checkout contains nonregular files')
                target=workspace/name;target.parent.mkdir(parents=True,exist_ok=True)
                with archive.extractfile(member) as source,target.open('xb') as output:shutil.copyfileobj(source,output)
        envelope=fetch('promotion',None,workspace,int(time.time()))
        if envelope is None:raise ContractError('no retained successful production checkpoint')
        private=workspace/'.atlas-private'
        state=json.loads((private/'workflow-context.json').read_bytes())
        deployed=json.loads((private/'production-deployment.json').read_bytes())
        if deployed.get('status')!='verified' or deployed.get('environment')!='production':
            raise ContractError('prior deployment lacks successful production verification')
        public=workspace/'build-private/frozen-production';public.parent.mkdir(parents=True,exist_ok=True)
        artifact(state['candidate_run_id'],'atlas-production-public',public,3072*1024**2)
        artifact(state['candidate_run_id'],'production-candidate-evidence',workspace/'reports',64*1024**2)
        report=ROOT/'reports/rollback.json'
        argv=['python','tools/release_contract/pages.py','rollback','--public',str(public),
            '--qualification-receipt',str(private/'production-receipt.json'),
            '--evidence',str(private/'production-acceptance.json'),'--automatic',
            '--deployment-id',deployed['deployment_id'],'--head',state['head_sha'],
            '--account',os.environ['ATLAS_ACCOUNT'],'--project',os.environ['ATLAS_PROJECT'],'--report',str(report)]
        with tempfile.TemporaryFile() as log:
            result=subprocess.run(argv,cwd=workspace,stdout=log,stderr=log)
        if result.returncode:raise ContractError('prior candidate is not currently eligible for rollback')
        return json.loads(report.read_bytes())

if __name__=='__main__':
    try:restore()
    except (ContractError,OSError,ValueError,KeyError,subprocess.SubprocessError):
        (ROOT/'reports/rollback.json').write_text(json.dumps({'status':'unavailable','reason':'no-independently-current-retained-candidate'})+'\n')
        raise SystemExit(1)
