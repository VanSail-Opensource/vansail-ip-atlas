"""Run production work in an enforced standard-size cgroup on GitHub Ubuntu."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time
import uuid

CPU_QUOTA = 200_000
MEMORY = 8 * 1024**3
WORKSPACE = 14 * 1024**3
RESERVE = 1024**3

def cgroup() -> Path:
    lines=Path('/proc/self/cgroup').read_text().splitlines()
    paths=[line[3:] for line in lines if line.startswith('0::')]
    if len(paths)!=1: raise RuntimeError('unified cgroup v2 required')
    root=Path('/sys/fs/cgroup')/paths[0].lstrip('/')
    if not root.resolve().is_relative_to(Path('/sys/fs/cgroup')): raise RuntimeError('invalid cgroup')
    return root

def slice_cgroup(name: str) -> Path:
    if not re.fullmatch(r'atlas[0-9a-f]{32}\.slice', name):
        raise RuntimeError('invalid runner budget slice')
    group=subprocess.check_output(['systemctl','show',name,'--property=ControlGroup','--value'],text=True).strip()
    if not group.startswith('/') or any(part in ('.','..') for part in group.split('/')):
        raise RuntimeError('invalid runner slice cgroup')
    root=Path('/sys/fs/cgroup')/group.lstrip('/')
    if root.name!=name or not root.resolve().is_relative_to(Path('/sys/fs/cgroup')):
        raise RuntimeError('runner slice cgroup differs')
    return root

def require_descendant(child: Path, parent: Path) -> None:
    if child.resolve()==parent.resolve() or not child.resolve().is_relative_to(parent.resolve()):
        raise RuntimeError('workload escaped the aggregate runner budget')

def usage(root: Path) -> int:
    # Count every writable task directory, including input checkpoints, caches and staging.
    total=0;seen=set()
    for current,dirs,files in os.walk(root,followlinks=False):
        for name in files:
            path=Path(current)/name
            try:
                if not path.is_symlink():
                    info=path.stat();identity=(info.st_dev,info.st_ino)
                    if identity not in seen:
                        seen.add(identity);total += info.st_blocks * 512
            except FileNotFoundError: pass
    return total

def effective(root: Path) -> dict:
    quota,period=(root/'cpu.max').read_text().split()
    maximum=(root/'memory.max').read_text().strip()
    swap=(root/'memory.swap.max').read_text().strip()
    if quota=='max' or int(quota)*100_000//int(period)!=CPU_QUOTA or maximum!=str(MEMORY) or swap!='0':
        raise RuntimeError('standard execution limits are not enforced')
    return {'scope':'github-hosted-cgroup-v2','cpu_quota_us':int(quota),'cpu_period_us':int(period),
            'memory_max_bytes':int(maximum),'swap_max_bytes':0,'workspace_limit_bytes':WORKSPACE}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inside',action='store_true')
    parser.add_argument('--report',type=Path,default=Path('reports/runner-budget.json'))
    parser.add_argument('command',nargs=argparse.REMAINDER)
    args=parser.parse_args(); command=args.command
    if command and command[0]=='--': command=command[1:]
    if not command: parser.error('command required')
    if sys.platform!='linux': raise SystemExit('production measurements require official Linux runners')
    if not args.inside:
        import pwd
        user=pwd.getpwuid(os.getuid()).pw_name
        identity=uuid.uuid4().hex
        unit='atlas-'+identity
        budget_slice='atlas'+identity+'.slice'
        environment={**os.environ,'ATLAS_RUNNER_SLICE':budget_slice}
        # sudo's secure_path applies even with -E. Restore only PATH after sudo
        # so children can find the pinned Python/Go/Node tools and workspace age.
        argv=['sudo','-E','env','PATH='+os.environ['PATH'],'/usr/bin/systemd-run','--quiet','--scope','--unit',unit,
              '--slice',budget_slice,
              '-p','CPUQuota=200%','-p','CPUQuotaPeriodSec=100ms','-p','MemoryMax=8G','-p','MemorySwapMax=0',
              '/usr/sbin/runuser','--user',user,'--preserve-environment','--',
              sys.executable,str(Path(__file__).resolve()),'--inside','--report',str(args.report),'--',*command]
        # A slice accounts both this scope and Chrome's separately measured scope.
        # Apply its limits before launching any task process, never after the fact.
        try:
            subprocess.run(['sudo','systemctl','start',budget_slice],check=True)
            subprocess.run(['sudo','systemctl','set-property','--runtime',budget_slice,
                'CPUQuota=200%','CPUQuotaPeriodSec=100ms','MemoryMax=8G','MemorySwapMax=0'],check=True)
            effective(slice_cgroup(budget_slice))
            status=subprocess.call(argv,env=environment)
        finally:
            subprocess.run(['sudo','systemctl','stop',budget_slice],check=False,
                           stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        raise SystemExit(status)
    root=slice_cgroup(os.environ.get('ATLAS_RUNNER_SLICE',''))
    require_descendant(cgroup(),root)
    profile=effective(root); workspace=Path(os.environ['GITHUB_WORKSPACE']).resolve()
    profile_path=workspace/'build-private/runner-profile.json';profile_path.parent.mkdir(exist_ok=True)
    profile_path.write_text(json.dumps(profile));os.environ['ATLAS_RUNNER_PROFILE']=str(profile_path)
    report={'schema_version':1,'execution_envelope':profile,'raw_host':{'logical_cpus':os.cpu_count(),
       'memory_bytes':os.sysconf('SC_PAGE_SIZE')*os.sysconf('SC_PHYS_PAGES'),'disk_bytes':shutil.disk_usage(workspace).total},
       'workspace_peak_bytes':0,'physical_free_low_water_bytes':shutil.disk_usage(workspace).free,'errors':[]}
    start=time.monotonic();process=subprocess.Popen(command,start_new_session=True)
    try:
        while True:
            # Stable Chrome is installed by Playwright outside the workspace.
            occupied=usage(workspace)+usage(Path('/opt/google/chrome'))
            free=shutil.disk_usage(workspace).free
            report['workspace_peak_bytes']=max(report['workspace_peak_bytes'],occupied)
            report['physical_free_low_water_bytes']=min(report['physical_free_low_water_bytes'],free)
            if occupied>=WORKSPACE-RESERVE or free<RESERVE:
                report['errors'].append('workspace-reserve-exhausted')
                os.killpg(process.pid,signal.SIGKILL)
            if process.poll() is not None: break
            time.sleep(.25)
        report['exit_code']=process.returncode
    finally:
        if process.poll() is None: os.killpg(process.pid,signal.SIGKILL);process.wait()
        report['runtime_ms']=(time.monotonic()-start)*1000
        report['cgroup_memory_peak_bytes']=int((root/'memory.peak').read_text())
        report['memory_events']={k:int(v) for k,v in (line.split() for line in (root/'memory.events').read_text().splitlines())}
        args.report.parent.mkdir(parents=True,exist_ok=True);args.report.write_text(json.dumps(report)+'\n')
    raise SystemExit(0 if process.returncode==0 and not report['errors'] and not report['memory_events'].get('oom_kill') else 1)

if __name__=='__main__': main()
