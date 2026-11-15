"""Measure a fresh complete Chrome process tree from birth with cgroup v2 peak."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from tools.release_contract.contracts import ContractError
from tools.hosted.memory_profile import verify_memory_profile

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--public',type=Path,required=True)
    parser.add_argument('--preview-url',required=True)
    parser.add_argument('--report',type=Path,default=ROOT/'reports/worker-memory.json')
    args=parser.parse_args()
    report={'accounting':'isolated-cgroup-v2-memory.peak','profile_exercised':None,
        'includes_worker_children':True,'accounting_scope':'entire-Chrome-tree-from-process-birth',
        'peak_bytes':None,'errors':[]}
    process=None;unit='atlas-worker-memory-'+uuid.uuid4().hex
    try:
        if sys.platform!='linux' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted':
            raise ContractError('worker peak proof requires official Linux runner')
        import pwd
        user=pwd.getpwuid(os.getuid()).pw_name
        private=ROOT/'.atlas-private';private.mkdir(exist_ok=True,mode=0o700)
        profile=private/'worker-memory-profile.json'
        with tempfile.TemporaryFile(dir=private) as log:
            result=subprocess.run(['build-private/atlas','memory-profile','-out','build-private/worker-profile',
                '-profile',str(profile)],cwd=ROOT,stdout=log,stderr=log)
            if result.returncode: raise ContractError('accepted worst-case fixture generation failed')
        raw=profile.read_bytes();value=json.loads(raw)
        if (value.get('schema_version')!=1 or value.get('scope')!='accepted-worst-case-browser-profile'
            or value.get('coverage')!={'decoded_object_bytes':33554432,'live_decoded_bytes':100663296,
                                    'answer_bytes':8388608,'decoder_window_bytes':8388608}
            or not isinstance(value.get('cases'),list) or not value['cases']):
            raise ContractError('accepted worst-case profile incomplete')
        report['raw_profile_sha256']=hashlib.sha256(raw).hexdigest()
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        with tempfile.TemporaryDirectory(prefix='chrome-memory-',dir=ROOT/'build-private') as temporary, tempfile.TemporaryFile(dir=private) as log:
            argv=['sudo','-E','systemd-run','--scope','--quiet','--unit',unit,
                '-p','CPUQuota=200%','-p','MemoryMax=384M','-p','MemorySwapMax=0',
                'runuser','--user',user,'--preserve-environment','--',
                '/opt/google/chrome/chrome','--headless=new','--no-sandbox','--disable-dev-shm-usage',
                '--disable-background-networking','--no-first-run','--no-default-browser-check',
                '--remote-debugging-address=127.0.0.1',f'--remote-debugging-port={port}',
                '--user-data-dir='+temporary,'about:blank']
            process=subprocess.Popen(argv,stdout=log,stderr=log)
            endpoint=f'http://127.0.0.1:{port}'
            deadline=time.monotonic()+45
            while time.monotonic()<deadline:
                if process.poll() is not None: raise ContractError('isolated Chrome failed to start')
                try:
                    with urllib.request.urlopen(endpoint+'/json/version',timeout=1) as response:
                        if response.status==200: break
                except OSError: time.sleep(.1)
            else: raise ContractError('isolated Chrome startup timed out')
            group=subprocess.check_output(['systemctl','show',unit+'.scope','--property=ControlGroup','--value'],text=True).strip()
            if not group.startswith('/') or '..' in group.split('/'): raise ContractError('invalid Chrome cgroup')
            group_root=Path('/sys/fs/cgroup')/group.lstrip('/')
            if (group_root/'memory.max').read_text().strip()!=str(384*1024**2):
                raise ContractError('Chrome memory limit unavailable')
            environment={**os.environ,'ATLAS_MEMORY_CDP':endpoint,'ATLAS_MEMORY_PUBLIC':str(args.public.resolve()),
                         'ATLAS_MEMORY_PROFILE':str(profile),'ATLAS_MEMORY_CASE_REPORT':str(private/'worker-memory-cases.json')}
            result=subprocess.run(['node','tools/hosted/worker-memory.mjs'],cwd=ROOT,env=environment,stdout=log,stderr=log,timeout=900)
            report['peak_bytes']=int((group_root/'memory.peak').read_text())
            report['memory_events']={k:int(v) for k,v in (line.split() for line in (group_root/'memory.events').read_text().splitlines())}
            if result.returncode or report['memory_events'].get('oom_kill') or report['memory_events'].get('oom'):
                raise ContractError('worst-case Chrome workload failed or exceeded memory')
            cases=json.loads((private/'worker-memory-cases.json').read_bytes())
            verify_memory_profile(value,cases,ROOT/'build-private/worker-profile')
            report.update(profile_exercised=value['scope'],cases=cases,
                          browser=cases['browser'],worker_sha256=cases['worker_sha256'])
            if not 0<report['peak_bytes']<384*1024**2:
                raise ContractError('worker memory gate failed')
    except (ContractError,OSError,ValueError,KeyError,subprocess.SubprocessError):
        report['errors'].append('worst-case-worker-memory-proof-failed')
    finally:
        if process is not None:
            subprocess.run(['sudo','systemctl','stop',unit+'.scope'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            try: process.wait(timeout=15)
            except subprocess.TimeoutExpired: process.kill();process.wait()
        args.report.parent.mkdir(parents=True,exist_ok=True);args.report.write_text(json.dumps(report)+'\n')
    return 1 if report['errors'] else 0

if __name__=='__main__':raise SystemExit(main())
