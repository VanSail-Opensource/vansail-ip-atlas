"""Measure a fresh complete Chrome process tree from birth with cgroup v2 peak."""
from __future__ import annotations
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import uuid

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from tools.release_contract.contracts import ContractError
from tools.hosted.memory_profile import verify_memory_profile
from tools.hosted.runner_budget import cgroup, effective, require_descendant, slice_cgroup

# These are the background-only subset of the pinned Playwright Chrome defaults.
# Keep GPU/rendering, networking, storage, the decoder and every measured case.
BACKGROUND_FLAGS=(
    '--disable-component-extensions-with-background-pages','--disable-component-update',
    '--disable-default-apps','--disable-extensions','--disable-sync','--disable-breakpad',
    '--metrics-recording-only','--no-service-autorun','--disable-updater-scheduler',
    '--disable-search-engine-choice-screen','--password-store=basic','--use-mock-keychain',
    '--disable-features=MediaRouter,OptimizationHints,NetworkTimeServiceQuerying,AimEnabled,PreconnectToSearch',
    '--enable-features=SkipListAccountsWithoutGaiaCookies',
)
MEMORY_STAT_FIELDS=frozenset({'anon','file','kernel','shmem','file_mapped','pagetables','sock','slab'})

def memory_snapshot(root: Path) -> dict:
    counters={name:int(value) for name,value in
              (line.split() for line in (root/'memory.stat').read_text().splitlines()) if name in MEMORY_STAT_FIELDS}
    return {'current_bytes':int((root/'memory.current').read_text()),
            'peak_bytes':int((root/'memory.peak').read_text()),'stat_bytes':counters}

def safe_progress(path: Path) -> dict | None:
    """Only fixed synthetic phase names cross into public failure evidence."""
    try:
        value=json.loads(path.read_bytes()).get('progress')
    except (OSError,ValueError,AttributeError):
        return None
    if (type(value) is not dict or set(value)!={'phase','case_name','completed_cases'}
        or value['phase'] not in ('connecting','ready','first-lookup','first-answer','repeat-lookup',
                                'repeat-answer','retained-answers','complete')
        or value['case_name'] not in (None,'maximum-materialized-answer','maximum-live-decoded','live-limit-rejection')
        or type(value['completed_cases']) is not int or not 0<=value['completed_cases']<=3):
        return None
    return value

def record_memory_sample(summary: dict, snapshot: dict, progress: dict | None, elapsed_ms: float) -> None:
    # Retain two observations only, even during a long or stuck workload.
    observation={'elapsed_ms':elapsed_ms,'current_bytes':snapshot['current_bytes'],
        'peak_bytes':snapshot['peak_bytes'],
        'stat_bytes':{key:value for key,value in snapshot['stat_bytes'].items() if key in MEMORY_STAT_FIELDS},
        'workload_progress':progress}
    summary['sample_count']+=1
    highest=summary.get('highest_sampled_current')
    if highest is None or observation['current_bytes']>highest['current_bytes']:
        summary['highest_sampled_current']=observation
    latest=summary.get('latest_observed_peak_increase')
    if latest is None or observation['peak_bytes']>latest['peak_bytes']:
        summary['latest_observed_peak_increase']=observation

@contextmanager
def sample_workload_memory(root: Path, case_report: Path):
    summary={'scope':'diagnostic-only-sampled-cgroup-memory','poll_ms':50,'sample_count':0,'read_error_count':0,
        'blind_spots':'polling gaps; cgroup counters and workload phase are read non-atomically'}
    stop=threading.Event();started=time.monotonic()
    def sample():
        while not stop.is_set():
            try:
                record_memory_sample(summary,memory_snapshot(root),safe_progress(case_report),
                                     (time.monotonic()-started)*1000)
            except (OSError,ValueError):
                summary['read_error_count']+=1
            stop.wait(.05)
    sampler=threading.Thread(target=sample,name='atlas-memory-diagnostics',daemon=True)
    sampler.start()
    try:
        yield summary
    finally:
        stop.set()
        # Never hide a workload timeout/failure behind diagnostic teardown.
        sampler.join(timeout=1)
        summary['sampling_stopped']=not sampler.is_alive()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--public',type=Path,required=True)
    parser.add_argument('--preview-url',required=True)
    parser.add_argument('--report',type=Path,default=ROOT/'reports/worker-memory.json')
    args=parser.parse_args()
    report={'accounting':'isolated-cgroup-v2-memory.peak','profile_exercised':None,
        'includes_worker_children':True,'accounting_scope':'entire-Chrome-tree-from-process-birth',
        'peak_bytes':None,'errors':[],'phase':'environment'}
    process=None;unit='atlas-worker-memory-'+uuid.uuid4().hex
    group_root=None
    case_report=ROOT/'.atlas-private/worker-memory-cases.json'
    try:
        case_report.unlink(missing_ok=True)
        if sys.platform!='linux' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted':
            raise ContractError('worker peak proof requires official Linux runner')
        import pwd
        user=pwd.getpwuid(os.getuid()).pw_name
        budget_slice=os.environ.get('ATLAS_RUNNER_SLICE','')
        budget_group=slice_cgroup(budget_slice)
        require_descendant(cgroup(),budget_group)
        effective(budget_group)
        private=ROOT/'.atlas-private';private.mkdir(exist_ok=True,mode=0o700)
        profile=private/'worker-memory-profile.json'
        report['phase']='fixture-generation'
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
            report['phase']='browser-start'
            argv=['sudo','-E','systemd-run','--scope','--quiet','--unit',unit,
                '--slice',budget_slice,
                '-p','CPUQuota=200%','-p','CPUQuotaPeriodSec=100ms','-p','MemoryMax=384M','-p','MemorySwapMax=0',
                'runuser','--user',user,'--preserve-environment','--',
                '/opt/google/chrome/chrome','--headless=new','--no-sandbox','--disable-dev-shm-usage',
                '--disable-background-networking','--no-first-run','--no-default-browser-check',
                *BACKGROUND_FLAGS,
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
            require_descendant(group_root,budget_group)
            if (group_root/'memory.max').read_text().strip()!=str(384*1024**2):
                raise ContractError('Chrome memory limit unavailable')
            report['baseline_memory']=memory_snapshot(group_root)
            environment={**os.environ,'ATLAS_MEMORY_CDP':endpoint,'ATLAS_MEMORY_PUBLIC':str(args.public.resolve()),
                         'ATLAS_MEMORY_PROFILE':str(profile),'ATLAS_MEMORY_CASE_REPORT':str(case_report)}
            report['phase']='workload'
            with sample_workload_memory(group_root,case_report) as sampled:
                report['sampled_memory']=sampled
                result=subprocess.run(['node','tools/hosted/worker-memory.mjs'],cwd=ROOT,env=environment,stdout=log,stderr=log,timeout=900)
            report['peak_bytes']=int((group_root/'memory.peak').read_text())
            report['memory_events']={k:int(v) for k,v in (line.split() for line in (group_root/'memory.events').read_text().splitlines())}
            if result.returncode or report['memory_events'].get('oom_kill') or report['memory_events'].get('oom'):
                raise ContractError('worst-case Chrome workload failed or exceeded memory')
            cases=json.loads((private/'worker-memory-cases.json').read_bytes())
            report['phase']='profile-verification'
            verify_memory_profile(value,cases,ROOT/'build-private/worker-profile')
            report.update(profile_exercised=value['scope'],cases=cases,
                          browser=cases['browser'],worker_sha256=cases['worker_sha256'])
            if not 0<report['peak_bytes']<384*1024**2:
                raise ContractError('worker memory gate failed')
            report['phase']='complete'
    except (ContractError,OSError,RuntimeError,ValueError,KeyError,subprocess.SubprocessError):
        report['errors'].append('worst-case-worker-memory-proof-failed')
    finally:
        if group_root is not None:
            try:report['final_memory']=memory_snapshot(group_root)
            except (OSError,ValueError):pass
        progress=safe_progress(case_report)
        if progress is not None:report['workload_progress']=progress
        if process is not None:
            subprocess.run(['sudo','systemctl','stop',unit+'.scope'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            try: process.wait(timeout=15)
            except subprocess.TimeoutExpired: process.kill();process.wait()
        args.report.parent.mkdir(parents=True,exist_ok=True);args.report.write_text(json.dumps(report)+'\n')
    return 1 if report['errors'] else 0

if __name__=='__main__':raise SystemExit(main())
