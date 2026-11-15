"""Encrypted, bounded state transfer between ephemeral trusted-main Actions jobs.

Only opaque ciphertext and the closed source-free envelope are uploaded. Age
authenticates ciphertext; GitHub's immutable artifact/run identity authenticates
the producer. Never accept ciphertext supplied by an arbitrary workflow/ref.
"""
from __future__ import annotations
import argparse
from datetime import datetime
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools.release_contract.contracts import ContractError, canonical_bytes, parse_canonical

REPOSITORY = 'VanSail-Opensource/vansail-ip-atlas'
WORKFLOWS = {'intake': '.github/workflows/production-intake.yml',
             'candidate': '.github/workflows/production-candidate.yml',
             'benchmark': '.github/workflows/production-benchmark-join.yml',
             'preview': '.github/workflows/production-preview.yml',
             'promotion': '.github/workflows/production-promotion.yml'}
MAX_BYTES = 8 * 1024**3
MAX_FILES = 100_000
RETENTION = 168 * 3600
STATE_FILES = frozenset({'state-v1.json','state-seal.key','state-seal-v2.json','publication-clocks-v1.json',
    'tier1-history-v2.json','production-receipt.json','production-acceptance.json',
    'production-browser-corpus.json','production-build.json','workflow-context.json','intake-report-v1.json','production-deployment.json'})
STATE_DIRECTORIES = frozenset({'records-v2','state-history-v2','production-receipts-v1'})
ENVELOPE_KEYS = {'format_version','kind','repository','head_sha','run_id','run_attempt',
                 'created_at','expires_at','ciphertext_sha256','ciphertext_bytes','key_id'}

def digest(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def api(route: str, *, output: Path | None = None):
    if not re.fullmatch(r'[A-Za-z0-9_/.?=&%+-]+', route):
        raise ContractError('invalid checkpoint API route')
    if output is not None:
        with output.open('xb') as stream:
            result = subprocess.run(['gh','api',f'repos/{REPOSITORY}/{route}'], stdout=stream,
                                    stderr=subprocess.DEVNULL, timeout=900)
        if result.returncode or output.stat().st_size > MAX_BYTES:
            raise ContractError('checkpoint transfer failed or exceeded budget')
        return None
    result = subprocess.run(['gh','api',f'repos/{REPOSITORY}/{route}'], stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=90)
    if result.returncode or len(result.stdout) > 8 * 1024**2:
        raise ContractError('checkpoint metadata unavailable')
    return json.loads(result.stdout)

def validate_envelope(value: dict, now: int) -> dict:
    if (type(value) is not dict or set(value) != ENVELOPE_KEYS or value['format_version'] != 1
            or value['repository'] != REPOSITORY or value['kind'] not in WORKFLOWS
            or not re.fullmatch(r'[0-9a-f]{40}', str(value['head_sha']))
            or not re.fullmatch(r'[0-9a-f]{64}', str(value['ciphertext_sha256']))
            or not re.fullmatch(r'[0-9a-f]{16}', str(value['key_id']))
            or any(type(value[k]) is not int for k in ('run_id','run_attempt','created_at','expires_at','ciphertext_bytes'))
            or value['run_id'] < 1 or value['run_attempt'] < 1
            or not 0 < value['ciphertext_bytes'] <= MAX_BYTES
            or not 0 <= value['created_at'] <= now < value['expires_at'] <= value['created_at'] + RETENTION):
        raise ContractError('invalid or expired checkpoint envelope')
    return value

def member_name(name: str) -> str:
    if (not name or '\\' in name or ':' in name or name.startswith('/')
            or any(p in ('','.','..') for p in name.split('/'))):
        raise ContractError('unsafe checkpoint path')
    parts = PurePosixPath(name).parts
    if (parts[0] != '.atlas-private' or len(parts)<2
            or not (len(parts)==2 and parts[1] in STATE_FILES or len(parts)>2 and parts[1] in STATE_DIRECTORIES)
            or name.endswith(('.partial','.log'))):
        raise ContractError('checkpoint path outside admitted state allowlist')
    return name

def pack(workspace: Path, output: Path, kind: str, now: int) -> dict:
    if os.environ.get('GITHUB_REPOSITORY') != REPOSITORY or os.environ.get('GITHUB_REF') != 'refs/heads/main':
        raise ContractError('checkpoint producer must run on trusted main')
    recipient = os.environ.get('ATLAS_STATE_AGE_RECIPIENT','')
    if not re.fullmatch(r'age1[0-9a-z]{58}', recipient):
        raise ContractError('checkpoint recipient unavailable')
    private = workspace / '.atlas-private'
    if not private.is_dir() or private.is_symlink() or not (private/'state-v1.json').is_file():
        raise ContractError('authenticated intake state unavailable')
    output.mkdir(parents=True, exist_ok=True)
    encrypted = output/'checkpoint.tar.gz.age'
    total = count = 0
    # No intermediate unencrypted archive is created. All producer stderr stays private.
    with encrypted.open('xb') as destination, tempfile.TemporaryFile() as errors:
        process = subprocess.Popen(['age','--encrypt','--recipient',recipient], stdin=subprocess.PIPE,
                                   stdout=destination, stderr=errors)
        try:
            with tarfile.open(fileobj=process.stdin, mode='w|gz') as archive:
                for path in sorted(private.rglob('*')):
                    if path.is_symlink():
                        raise ContractError('checkpoint cannot contain links')
                    if path.is_dir():
                        continue
                    name = path.relative_to(workspace).as_posix()
                    try: member_name(name)
                    except ContractError: continue  # Explicitly quarantined/temporary files never leave the runner.
                    info = path.stat()
                    if not stat.S_ISREG(info.st_mode):
                        raise ContractError('checkpoint requires regular files')
                    total += info.st_size; count += 1
                    if total > MAX_BYTES - 64 * 1024**2 or count > MAX_FILES:
                        raise ContractError('checkpoint plaintext budget exceeded')
                    entry = tarfile.TarInfo(name); entry.size = info.st_size; entry.mode = 0o600
                    with path.open('rb') as source: archive.addfile(entry, source)
            process.stdin.close()
            if process.wait(timeout=900): raise ContractError('checkpoint encryption failed')
        finally:
            if process.poll() is None: process.kill(); process.wait()
    state=json.loads((private/'state-v1.json').read_bytes())
    deadlines=[int(datetime.fromisoformat(source['ExpiresAt'].replace('Z','+00:00')).timestamp()) for source in state.get('Sources',[])]
    expiry=min([now+RETENTION,*deadlines])
    envelope = {'format_version':1,'kind':kind,'repository':REPOSITORY,
        'head_sha':os.environ['GITHUB_SHA'],'run_id':int(os.environ['GITHUB_RUN_ID']),
        'run_attempt':int(os.environ.get('GITHUB_RUN_ATTEMPT','1')),'created_at':now,'expires_at':expiry,
        'ciphertext_sha256':digest(encrypted),'ciphertext_bytes':encrypted.stat().st_size,
        'key_id':hashlib.sha256(recipient.encode()).hexdigest()[:16]}
    validate_envelope(envelope, now)
    (output/'envelope.json').write_bytes(canonical_bytes(envelope))
    return envelope

def extract_authenticated(stream, workspace: Path) -> None:
    count = total = 0; seen = set()
    # Called only after the entire age stream has authenticated successfully.
    with tarfile.open(fileobj=stream, mode='r:*') as archive:
        for entry in archive:
            name = member_name(entry.name)
            count += 1; total += entry.size
            if (name in seen or not entry.isfile() or entry.size < 0 or count > MAX_FILES or total > MAX_BYTES
                    or entry.pax_headers or entry.mode & 0o7000):
                raise ContractError('invalid checkpoint archive member')
            seen.add(name)
            target = workspace / name
            for parent in (target, *target.parents):
                if parent == workspace.parent: break
                if parent.is_symlink(): raise ContractError('checkpoint destination traverses link')
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with archive.extractfile(entry) as source, target.open('xb') as destination:
                shutil.copyfileobj(source, destination, length=1024*1024)
            target.chmod(0o600)
    if '.atlas-private/state-v1.json' not in seen:
        raise ContractError('checkpoint has no authenticated state')

def unpack(directory: Path, workspace: Path, trusted_run: dict, now: int) -> dict:
    envelope = validate_envelope(parse_canonical((directory/'envelope.json').read_bytes()), now)
    if (trusted_run.get('status') != 'completed' or trusted_run.get('conclusion') != 'success'
            or trusted_run.get('path') != WORKFLOWS[envelope['kind']]
            or trusted_run.get('head_branch') != 'main'
            or trusted_run.get('head_repository',{}).get('full_name') != REPOSITORY
            or trusted_run.get('event') not in ('push','schedule','workflow_dispatch','workflow_run')
            or trusted_run.get('id') != envelope['run_id'] or trusted_run.get('run_attempt') != envelope['run_attempt']
            or trusted_run.get('head_sha') != envelope['head_sha']):
        raise ContractError('checkpoint producer identity is not trusted')
    encrypted = directory/'checkpoint.tar.gz.age'
    if encrypted.stat().st_size != envelope['ciphertext_bytes'] or digest(encrypted) != envelope['ciphertext_sha256']:
        raise ContractError('checkpoint ciphertext identity differs')
    secret = os.environ.get('ATLAS_STATE_AGE_IDENTITY','')
    if not secret or (workspace/'.atlas-private').exists():
        raise ContractError('checkpoint identity unavailable or destination not empty')
    # Decrypt to a private temporary file; extraction cannot observe unauthenticated partial bytes.
    with tempfile.TemporaryDirectory(prefix='atlas-open-', dir=workspace) as temporary:
        root = Path(temporary); root.chmod(0o700)
        identity = root/'identity'; identity.write_text(secret); identity.chmod(0o600)
        archive = root/'checkpoint.tar.gz'
        with archive.open('xb') as plaintext:
            result = subprocess.run(['age','--decrypt','--identity',str(identity),str(encrypted)],
                                    stdout=plaintext, stderr=subprocess.DEVNULL, timeout=900)
        identity.unlink()
        if result.returncode or archive.stat().st_size > MAX_BYTES:
            raise ContractError('checkpoint authentication failed')
        with archive.open('rb') as source: extract_authenticated(source, workspace)
    return envelope

def fetch(kind: str, run_id: int | None, workspace: Path, now: int) -> dict | None:
    if os.environ.get('GITHUB_REPOSITORY') != REPOSITORY or os.environ.get('GITHUB_REF') != 'refs/heads/main':
        raise ContractError('checkpoint restore must run on trusted main')
    if run_id is None:
        workflow = WORKFLOWS[kind].split('/')[-1]
        runs = api(f'actions/workflows/{workflow}/runs?branch=main&status=success&per_page=20')['workflow_runs']
    else:
        runs = [api(f'actions/runs/{run_id}')]
    for run in runs:
        listing = api(f"actions/runs/{run['id']}/artifacts?per_page=100")
        matches = [a for a in listing['artifacts'] if a['name'] == f'atlas-{kind}-checkpoint' and not a['expired']]
        if not matches: continue
        if len(matches) != 1: raise ContractError('checkpoint artifact identity ambiguous')
        artifact = matches[0]
        if (artifact.get('workflow_run',{}).get('head_sha') != run['head_sha']
                or not 0 < artifact['size_in_bytes'] <= MAX_BYTES
                or not re.fullmatch(r'sha256:[0-9a-f]{64}',artifact.get('digest',''))):
            raise ContractError('checkpoint GitHub artifact binding differs')
        with tempfile.TemporaryDirectory(prefix='atlas-transfer-',dir=workspace) as temporary:
            root=Path(temporary); bundle=root/'artifact.zip'
            api(f"actions/artifacts/{artifact['id']}/zip",output=bundle)
            if digest(bundle) != artifact['digest'][7:]: raise ContractError('checkpoint artifact digest differs')
            with zipfile.ZipFile(bundle) as archive:
                if sorted(archive.namelist()) != ['checkpoint.tar.gz.age','envelope.json']:
                    raise ContractError('checkpoint artifact members differ')
                for entry in archive.infolist():
                    if entry.file_size > MAX_BYTES or stat.S_IFMT(entry.external_attr>>16) not in (0,stat.S_IFREG):
                        raise ContractError('checkpoint artifact exceeds bound')
                    with archive.open(entry) as source, (root/entry.filename).open('xb') as destination:
                        shutil.copyfileobj(source,destination,1024*1024)
            bundle.unlink()
            saved=parse_canonical((root/'envelope.json').read_bytes())
            if type(saved.get('expires_at')) is int and saved['expires_at']<=now:
                continue
            return unpack(root, workspace, run, now)
    if run_id is not None: raise ContractError('requested checkpoint unavailable')
    return None

def prune(now: int) -> int:
    """Delete expired ciphertext promptly; retain only two recent checkpoints/kind.

    The tiny separate envelope artifact avoids downloading private multi-GiB
    ciphertext merely to inspect its public expiry. Only trusted producer runs
    and this module's exact artifact names are eligible for deletion.
    """
    if os.environ.get('GITHUB_REPOSITORY')!=REPOSITORY or os.environ.get('GITHUB_REF')!='refs/heads/main':
        raise ContractError('checkpoint retention requires trusted main')
    entries=[]
    for page in range(1,21):
        values=api(f'actions/artifacts?per_page=100&page={page}')['artifacts']
        entries.extend(values)
        if len(values)<100:break
    indexed={}
    for entry in entries:
        run=entry.get('workflow_run',{}).get('id')
        for kind in WORKFLOWS:
            if entry.get('name')==f'atlas-{kind}-checkpoint-index':indexed[(kind,run)]=entry
    retained={kind:0 for kind in WORKFLOWS};deleted=0
    for (kind,run_id),index in sorted(indexed.items(),key=lambda pair:pair[1]['id'],reverse=True):
        run=api(f'actions/runs/{run_id}')
        if (run.get('status')!='completed' or run.get('conclusion')!='success'
            or run.get('path')!=WORKFLOWS[kind] or run.get('head_branch')!='main'
            or run.get('head_repository',{}).get('full_name')!=REPOSITORY):continue
        matches=[entry for entry in entries if entry.get('workflow_run',{}).get('id')==run_id
                 and entry.get('name')==f'atlas-{kind}-checkpoint']
        if len(matches)!=1:continue
        remove=index.get('expired') is True
        if not remove:
            if not 0<index['size_in_bytes']<65536:raise ContractError('checkpoint expiry index exceeds bound')
            with tempfile.TemporaryDirectory(prefix='atlas-retention-') as temporary:
                path=Path(temporary)/'index.zip';api(f"actions/artifacts/{index['id']}/zip",output=path)
                if index.get('digest')!='sha256:'+digest(path):raise ContractError('checkpoint expiry index digest differs')
                with zipfile.ZipFile(path) as archive:
                    if archive.namelist()!=['envelope.json'] or archive.getinfo('envelope.json').file_size>4096:
                        raise ContractError('checkpoint expiry index population differs')
                    envelope=parse_canonical(archive.read('envelope.json'))
                validate_envelope(envelope,envelope['created_at'])
                if envelope['run_id']!=run_id or envelope['kind']!=kind or envelope['head_sha']!=run['head_sha']:
                    raise ContractError('checkpoint expiry index producer differs')
                remove=envelope['expires_at']<=now or (retained[kind]>=2 and now-envelope['created_at']>=48*3600)
        retained[kind]+=1
        if remove:
            for entry in [matches[0],index]:
                result=subprocess.run(['gh','api','--method','DELETE',f"repos/{REPOSITORY}/actions/artifacts/{entry['id']}"],
                    stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=90)
                if result.returncode:raise ContractError('expired checkpoint deletion failed')
                deleted+=1
    return deleted

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation',choices=('pack','restore','prune'))
    parser.add_argument('--kind',choices=tuple(WORKFLOWS))
    parser.add_argument('--workspace',type=Path,default=ROOT)
    parser.add_argument('--out',type=Path,default=ROOT/'build-private/checkpoint')
    parser.add_argument('--run-id',type=int)
    args=parser.parse_args()
    try:
        if args.operation=='prune':
            print(f'Checkpoint retention removed {prune(int(time.time()))} expired artifacts')
            return
        if not args.kind:raise ContractError('checkpoint kind required')
        result=pack(args.workspace,args.out,args.kind,int(time.time())) if args.operation=='pack' else fetch(args.kind,args.run_id,args.workspace,int(time.time()))
        print('Checkpoint '+('verified' if result else 'cold start: no retained checkpoint'))
    except (ContractError,OSError,ValueError,subprocess.SubprocessError,tarfile.TarError,zipfile.BadZipFile):
        print('Checkpoint transport failed; private details withheld',file=sys.stderr)
        raise SystemExit(1)

if __name__=='__main__': main()
