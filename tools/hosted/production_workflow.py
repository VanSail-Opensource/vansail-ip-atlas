"""Fixed trusted-main production stage commands; all private diagnostics stay local."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from tools.hosted.checkpoint import api, REPOSITORY, WORKFLOWS
from tools.release_contract.contracts import ContractError, canonical_bytes, sha256
from tools.release_contract.production import read_private

# Integration now includes intake plus the separately bounded real cold compile.
# This wait is orchestration headroom, not a build/performance threshold.
EXACT_HEAD_WAIT_SECONDS=105*60
STAGES=(*WORKFLOWS, 'benchmark_cases', 'benchmark_dispatch')
MATRIX_WORKFLOW='.github/workflows/production-benchmarks.yml'

COMMAND_PHASES={
    ('build-private/atlas','compile-production'):'compile-production',
    ('build-private/atlas','verify-production'):'verify-production',
    ('build-private/atlas','corpus'):'derive-query-corpus',
    ('python','tools/hosted/source_intake.py'):'source-intake',
    ('python','tools/release_contract/software_licenses.py'):'software-license-audit',
    ('python','tools/release_contract/prepare_static.py'):'package-static-candidate',
    ('python','tools/hosted/production-build.py'):'measure-production-builds',
    ('python','tools/hosted/candidate.py'):'verify-frozen-candidate',
    ('python','tools/release_contract/pages.py'):'pages-deployment',
    ('python','tools/hosted/worker_memory.py'):'measure-worker-memory',
    ('node','tools/hosted/production-browser.mjs'):'measure-production-browser',
    ('python','tools/release_contract/promotion.py'):'authorize-production',
    ('python','tools/hosted/rollback.py'):'verify-rollback',
    ('go','run'):'measure-native-lookup',
    ('npm','exec'):'frontend-tooling',
}

SAFE_FAILURES={
    'context deadline exceeded':'time-budget',
    'pipeline process RSS ceiling exceeded':'rss-budget',
    'pipeline physical free-space floor crossed':'disk-reserve',
    'pipeline scratch ceiling exceeded':'scratch-budget',
    'bulk scratch budget exceeded':'scratch-budget',
    'resource_limit':'object-resource-profile',
    'partition_budget':'object-partition-budget',
    'pipeline requires at least one public fact':'empty-public-data',
}

COMPILE_PHASES=frozenset({'stage','config','qualification','tier1','build','boundary',
    'objects','receipt','retention','history','seal','materialize-seed','materialize-paths',
    'materialize-asn-risk','materialize-spatial','materialize-asn','pipeline-sort',
    'pipeline-merge','pipeline-classify','pipeline-partition','pipeline-publish'})

COMPILE_COUNTER_PHASES=frozenset({'pipeline-sort','pipeline-merge','pipeline-classify',
    'pipeline-partition','pipeline-publish'})
COMPILE_COUNTER_FIELDS=frozenset({'input_records','unique_records','sort_runs','partitions',
    'binary_byte_repacks','sort_buffer_peak','partition_buffer_peak','output_bytes','scratch_peak'})

def compile_counter_diagnostics(path, start):
    """Expose only bounded aggregate counters from this command's complete lines."""
    def unique_object(pairs):
        row={}
        for key,value in pairs:
            if key in row: raise ValueError('duplicate compiler counter key')
            row[key]=value
        return row

    if type(start) is not int or start<0: return []
    records=[]
    try:
        with path.open('rb') as stream:
            stream.seek(0,2);end=stream.tell()
            if start>end: return []
            offset=max(start,end-65536)
            stream.seek(offset)
            data=stream.read(65536)
        if offset>start:
            # The bounded tail can begin inside an arbitrary private log line.
            data=data.partition(b'\n')[2]
        lines=data.split(b'\n')[:-1] # A failed/truncated final write is not evidence.
        if len(lines)>4096: return []
        for line in lines:
            prefix=b'ATLAS_COMPILE_COUNTERS '
            if not line.startswith(prefix) or len(line)>1024: continue
            try: row=json.loads(line[len(prefix):],object_pairs_hook=unique_object)
            except (ValueError,UnicodeDecodeError,RecursionError): continue
            if (type(row) is not dict or set(row)!=COMPILE_COUNTER_FIELDS|{'phase'}
                    or type(row['phase']) is not str or row['phase'] not in COMPILE_COUNTER_PHASES
                    or any(type(row[key]) is not int or not 0<=row[key]<=2**53-1
                           for key in COMPILE_COUNTER_FIELDS)):
                continue
            records.append(row)
            if len(records)>8: return []
    except OSError:
        return []
    return records

def compile_phase_diagnostics(path, start):
    """Read bounded fixed-schema diagnostics, never arbitrary child output."""
    records=[]
    stack=[]
    try:
        with path.open('rb') as stream:
            stream.seek(0,2);end=stream.tell();stream.seek(max(start,end-65536))
            lines=stream.read(65536).splitlines()
        for line in lines:
            prefix=b'ATLAS_COMPILE_PHASE '
            if not line.startswith(prefix) or len(line)>1024:
                continue
            try: row=json.loads(line[len(prefix):])
            except (ValueError,UnicodeDecodeError): continue
            if (type(row) is not dict or set(row)!={'phase','event','elapsed_ms','ok'}
                    or type(row['phase']) is not str or row['phase'] not in COMPILE_PHASES
                    or row['event'] not in ('begin','end')
                    or type(row['elapsed_ms']) is not int or not 0<=row['elapsed_ms']<=86400000
                    or type(row['ok']) is not bool):
                continue
            if row['event']=='begin':
                if row['elapsed_ms']!=0 or not row['ok']: continue
                stack.append(row['phase'])
            else:
                if not stack or stack.pop()!=row['phase']: return []
            records.append(row)
            if len(records)>64: return []
    except OSError:
        return []
    return records

def failure_category(path, start):
    # Classify only bounded current-command output into fixed labels. Raw text,
    # filenames, source identities and arbitrary exception messages stay private.
    try:
        with path.open('rb') as stream:
            stream.seek(0,2);end=stream.tell();stream.seek(max(start,end-65536))
            lines=stream.read(65536).decode('utf-8',errors='replace').splitlines()
        for line in reversed(lines):
            if line in SAFE_FAILURES: return SAFE_FAILURES[line]
            if line.startswith('production_blocked: unqualified source capabilities: '):
                return 'source-capability'
    except OSError:
        pass
    return 'command-failed'

def run(argv, *, output=None):
    private=ROOT/'.atlas-private';private.mkdir(exist_ok=True,mode=0o700)
    # Only these fixed labels may reach public logs. Never echo arbitrary argv,
    # exception text or child output, which can contain source-rich diagnostics.
    phase=COMMAND_PHASES.get(tuple(str(x) for x in argv[:2]),'stage-command')
    print('Production step started: '+phase,flush=True)
    # Never echo command arguments or source-specific parser errors to public logs.
    with (private/'stage.log').open('ab') as log:
        start=log.tell()
        result=subprocess.run([str(x) for x in argv],cwd=ROOT,stdout=output or log,stderr=log,check=False)
    if phase=='compile-production':
        for row in compile_phase_diagnostics(private/'stage.log',start):
            if row['event']=='begin':
                print('Production compiler phase entered: '+row['phase'],flush=True)
            else:
                print('Production compiler phase ended: '+row['phase']
                    +' elapsed_ms='+str(row['elapsed_ms'])+' ok='+str(row['ok']).lower(),flush=True)
        for row in compile_counter_diagnostics(private/'stage.log',start):
            print('Production compiler counters: '+json.dumps(row,sort_keys=True,separators=(',',':')),flush=True)
    if result.returncode:
        print('Production step failed: '+phase,file=sys.stderr,flush=True)
        print('Production failure category: '+failure_category(private/'stage.log',start),file=sys.stderr,flush=True)
        raise ContractError('production stage command failed; private diagnostics remain on runner')
    print('Production step completed: '+phase,flush=True)

def context(kind: str, upstream: int | None):
    if os.environ.get('GITHUB_REPOSITORY')!=REPOSITORY or os.environ.get('GITHUB_REF')!='refs/heads/main':
        raise ContractError('production orchestration requires trusted main')
    head=os.environ['GITHUB_SHA']
    if api('branches/main')['commit']['sha']!=head: raise ContractError('main changed before stage start')
    previous={'intake':'.github/workflows/p0-contracts.yml','candidate':WORKFLOWS['intake'],
              'benchmark_cases':WORKFLOWS['candidate'],'benchmark_dispatch':WORKFLOWS['candidate'],
              'benchmark':MATRIX_WORKFLOW,'preview':WORKFLOWS['benchmark'],'promotion':WORKFLOWS['preview']}[kind]
    if upstream is None:
        event=json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
        upstream=event.get('workflow_run',{}).get('id')
        if upstream is None and event.get('inputs',{}).get('upstream_run_id'):
            raw=event['inputs']['upstream_run_id']
            if not re.fullmatch(r'[1-9][0-9]{0,19}',raw): raise ContractError('invalid upstream run input')
            upstream=int(raw)
    if upstream is None and kind=='intake':
        deadline=time.monotonic()+EXACT_HEAD_WAIT_SECONDS
        while True:
            runs=api('actions/workflows/p0-contracts.yml/runs?branch=main&per_page=100')['workflow_runs']
            matches=[item for item in runs if item['head_sha']==head and item['event'] in ('push','workflow_dispatch')]
            if matches and matches[0]['status']=='completed':
                if matches[0]['conclusion']!='success':raise ContractError('exact-head integration failed')
                upstream=matches[0]['id'];break
            if os.environ.get('GITHUB_EVENT_NAME')!='push' or time.monotonic()>=deadline:
                raise ContractError('exact-head integration has not passed')
            if api('branches/main')['commit']['sha']!=head:raise ContractError('main changed while integration ran')
            time.sleep(15)
    if type(upstream) is not int or upstream<1: raise ContractError('trusted upstream run missing')
    value=api(f'actions/runs/{upstream}')
    if (value.get('head_sha')!=head or value.get('head_branch')!='main' or value.get('path')!=previous
        or value.get('head_repository',{}).get('full_name')!=REPOSITORY
        or value.get('status')!='completed' or value.get('conclusion')!='success'
        or value.get('event') not in ('push','workflow_dispatch','workflow_run','schedule')):
        raise ContractError('upstream run is not successful exact-head trusted main')
    attempt=value.get('run_attempt')
    if type(attempt) is not int or attempt<1: raise ContractError('upstream attempt unavailable')
    with open(os.environ['GITHUB_OUTPUT'],'a') as output: output.write(f'upstream_run_id={upstream}\nupstream_run_attempt={attempt}\n')
    with open(os.environ['GITHUB_ENV'],'a') as output: output.write(f'ATLAS_UPSTREAM_RUN={upstream}\nATLAS_UPSTREAM_ATTEMPT={attempt}\n')
    return upstream,attempt

CONTEXT_CHAIN=('integration','intake','candidate','benchmark_cases','benchmark','preview','promotion')

def read_context(stage):
    value=json.loads(read_private(ROOT/'.atlas-private/workflow-context.json'))
    keys={'format_version','head_sha'}
    for name in CONTEXT_CHAIN[:CONTEXT_CHAIN.index(stage)+1]:
        keys.update((name+'_run_id',name+'_run_attempt'))
    if (type(value) is not dict or set(value)!=keys or value.get('format_version')!=2
            or value.get('head_sha')!=os.environ['GITHUB_SHA']
            or any(type(value[key]) is not int or value[key]<1 for key in keys-{'format_version','head_sha'})):
        raise ContractError('encrypted production context does not bind the exact stage chain')
    return value


def update_context(kind):
    upstream=int(os.environ['ATLAS_UPSTREAM_RUN']);attempt=int(os.environ['ATLAS_UPSTREAM_ATTEMPT'])
    run_id=int(os.environ['GITHUB_RUN_ID']);run_attempt=int(os.environ['GITHUB_RUN_ATTEMPT'])
    if min(upstream,attempt,run_id,run_attempt)<1: raise ContractError('invalid stage run identity')
    if kind=='intake':
        value={'format_version':2,'head_sha':os.environ['GITHUB_SHA']}
        previous='integration'
    else:
        stored={'candidate':'intake','benchmark_cases':'candidate','benchmark':'candidate',
                'preview':'benchmark','promotion':'preview'}[kind]
        value=read_context(stored)
        previous='benchmark_cases' if kind=='benchmark' else stored
        if kind!='benchmark' and (value[previous+'_run_id']!=upstream or value[previous+'_run_attempt']!=attempt):
            raise ContractError('restored checkpoint differs from completed upstream attempt')
    value[previous+'_run_id']=upstream;value[previous+'_run_attempt']=attempt
    value[kind+'_run_id']=run_id;value[kind+'_run_attempt']=run_attempt
    path=ROOT/'.atlas-private/workflow-context.json'
    path.parent.mkdir(exist_ok=True,mode=0o700);path.write_bytes(canonical_bytes(value))
    return value


def dispatch_benchmarks():
    # The relay itself follows a COMPLETED candidate; workflow_dispatch resets
    # GitHub's three-level workflow_run chain without an unfinished producer.
    upstream,_=context('benchmark_dispatch',None)
    payload=canonical_bytes({'ref':'main','inputs':{'upstream_run_id':str(upstream)}})
    result=subprocess.run(['gh','api','--method','POST',f'repos/{REPOSITORY}/actions/workflows/production-benchmarks.yml/dispatches',
                           '--input','-'],input=payload,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=90)
    if result.returncode: raise ContractError('automatic benchmark dispatch failed')


def native_gate():
    from tools.hosted.production_benchmarks import verify_native_lookup
    candidate=json.loads(read_private(ROOT/'reports/static-candidate.json'))
    lookup=json.loads(read_private(ROOT/'reports/production-lookup.json',16*1024**2))
    verify_native_lookup(candidate,lookup)


def original_candidate(state):
    from tools.hosted.benchmark_transport import candidate_reports
    from tools.release_contract.promotion import TrustedCI
    _,reports=candidate_reports(TrustedCI(),state['candidate_run_id'],state['candidate_run_attempt'],os.environ['GITHUB_SHA'])
    directory=ROOT/'reports';directory.mkdir(exist_ok=True)
    for name,data in reports.items(): (directory/name).write_bytes(data)
    return reports


def verify_frozen_current():
    run(['python','tools/hosted/candidate.py','--public','build-private/frozen-production'])
    run(['build-private/atlas','verify-production','-workspace',ROOT,'-atlas','build-private/frozen-production/_atlas',
         '-receipt','.atlas-private/production-receipt.json'])


def benchmark_case(scenario,sample):
    state=update_context('benchmark_cases')
    original_candidate(state)
    verify_frozen_current()
    run(['python','tools/hosted/production-build.py','--atlas-binary','build-private/atlas',
         '--case',scenario,'--sample',sample,'--report','reports/production-build-case.json'])
    verify_frozen_current()


def benchmark_resolve():
    from tools.hosted.benchmark_transport import collect_cases,candidate_reports,positive
    from tools.release_contract.promotion import TrustedCI,json_object
    ci=TrustedCI();run_id=int(os.environ['ATLAS_UPSTREAM_RUN'])
    matrix,cases=collect_cases(ci,run_id,os.environ['GITHUB_SHA'])
    if matrix['run_attempt']!=int(os.environ['ATLAS_UPSTREAM_ATTEMPT']): raise ContractError('matrix attempt changed')
    first=json_object(cases[0]['case_report'])['identity']
    candidate=positive(first.get('candidate_run_id'));attempt=positive(first.get('candidate_run_attempt'))
    candidate_reports(ci,candidate,attempt,os.environ['GITHUB_SHA'])
    with open(os.environ['GITHUB_OUTPUT'],'a') as output:
        output.write(f'candidate_run_id={candidate}\ncandidate_run_attempt={attempt}\n')


def benchmark_join():
    from tools.hosted.benchmark_transport import collect_cases
    from tools.hosted.production_benchmarks import aggregate_reports,benchmark_identity
    from tools.release_contract.promotion import TrustedCI,json_object
    state=update_context('benchmark')
    reports=original_candidate(state)
    verify_frozen_current()
    matrix,cases=collect_cases(TrustedCI(),state['benchmark_cases_run_id'],os.environ['GITHUB_SHA'])
    if matrix['run_attempt']!=state['benchmark_cases_run_attempt']: raise ContractError('matrix attempt changed')
    candidate=json_object(reports['static-candidate.json'])
    receipt=json_object(read_private(ROOT/'.atlas-private/production-receipt.json'))
    identity=benchmark_identity(candidate,receipt,head_sha=os.environ['GITHUB_SHA'],
        candidate_run_id=state['candidate_run_id'],candidate_run_attempt=state['candidate_run_attempt'])
    aggregate=aggregate_reports(candidate,reports['production-lookup.json'],cases,identity=identity,
        benchmark_run_id=matrix['id'],benchmark_run_attempt=matrix['run_attempt'])
    verify_frozen_current()
    data=canonical_bytes(aggregate)
    (ROOT/'reports/production-build.json').write_bytes(data)
    (ROOT/'.atlas-private/production-build.json').write_bytes(data)


def cleanup_private():
    targets=[ROOT/'.atlas-private',*ROOT.glob('atlas-open-*'),*ROOT.glob('atlas-transfer-*'),
             *(ROOT/'build-private').glob('benchmark-*')]
    for target in targets:
        if target.exists() or target.is_symlink():
            if target.is_symlink() or not target.resolve().is_relative_to(ROOT):
                raise ContractError('unsafe private cleanup path')
            if target.is_dir(): shutil.rmtree(target)
            else: target.unlink()


def intake_clock():
    # Select the materialization clock from the restored state. The Go compiler
    # independently authenticates its seal and requires this exact evaluation.
    try:
        state=json.loads(read_private(ROOT/'.atlas-private/state-v1.json',64*1024**2))
    except ValueError as error:
        raise ContractError('invalid intake state clock') from error
    if type(state) is not dict or type(state.get('Version')) is not int or state['Version']!=2:
        raise ContractError('partitioned intake state required')
    value=state.get('EvaluatedAt')
    if not isinstance(value,str) or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z',value):
        raise ContractError('UTC whole-second intake clock required')
    try:
        clock=int(datetime.strptime(value,'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc).timestamp())
    except (ValueError,OverflowError) as error:
        raise ContractError('invalid intake state clock') from error
    if not 0<=clock<=int(time.time()):
        raise ContractError('intake clock is outside the current time interval')
    return clock

def candidate():
    clock=intake_clock();update_context('candidate');private=ROOT/'.atlas-private'
    receipt=private/'production-receipt.json';atlas=ROOT/'build-private/production-atlas'
    run(['build-private/atlas','compile-production','-workspace',ROOT,'-clock',clock,'-out',atlas,'-receipt',receipt])
    # Compilation is deterministic at intake time; eligibility must still hold
    # at the current wall clock before any corpus or public packaging is built.
    run(['build-private/atlas','verify-production','-workspace',ROOT,'-atlas',atlas,'-receipt',receipt])
    run(['build-private/atlas','corpus','-atlas',atlas,'-out',private/'production-browser-corpus.json'])
    pnpm=['npm','exec','--yes','--package','pnpm@11.28.12','--','pnpm','--dir','web']
    with (ROOT/'build-private/software-license-metadata.json').open('wb') as output:
        run([*pnpm,'licenses','list','--prod','--json'],output=output)
    run(['python','tools/release_contract/software_licenses.py'])
    run([*pnpm,'typecheck']);run([*pnpm,'generate'])
    run(['python','tools/release_contract/software_licenses.py','--bundle-audit','build-private/software-bundle-audit.json','--require-runtime-review'])
    run(['python','tools/release_contract/prepare_static.py','--atlas',atlas,'--qualification-receipt',receipt])
    run(['go','run','./tools/hosted/lookupbench','-atlas',atlas,'-corpus',private/'production-browser-corpus.json','-report','reports/production-lookup.json'])
    run(['python','tools/hosted/production_workflow.py','native-gate'])
    run(['python','tools/hosted/candidate.py','--public','web/.output/public'])

def preview():
    update_context('preview')
    run(['python','tools/release_contract/pages.py','preview','--public','build-private/frozen-production',
       '--qualification-receipt','.atlas-private/production-receipt.json','--account',os.environ['ATLAS_ACCOUNT'],
       '--project',os.environ['ATLAS_PROJECT'],'--head',os.environ['GITHUB_SHA']])
    deployment=json.loads((ROOT/'reports/pages-deployment.json').read_text())
    os.environ['ATLAS_PREVIEW_URL']=deployment['url']
    run(['python','tools/hosted/candidate.py','--public','build-private/frozen-production','--preview-url',deployment['url']])
    run(['python','tools/hosted/worker_memory.py','--public','build-private/frozen-production','--preview-url',deployment['url']])
    run(['node','tools/hosted/production-browser.mjs'])
    run(['python','tools/hosted/candidate.py','--public','build-private/frozen-production','--preview-url',deployment['url']])

def promotion():
    state=update_context('promotion')
    common=['--public','build-private/frozen-production','--qualification-receipt','.atlas-private/production-receipt.json',
            '--evidence','.atlas-private/production-acceptance.json']
    # Evidence belongs to this new attempt; never silently overwrite a prior accepted packet.
    packet=ROOT/'.atlas-private/production-acceptance.json'
    if packet.exists(): packet.unlink()
    run(['python','tools/release_contract/promotion.py',*common,'--assemble','--head',os.environ['GITHUB_SHA'],
        '--integration-run-id',state['integration_run_id'],'--candidate-run-id',state['candidate_run_id'],
        '--benchmark-run-id',state['benchmark_run_id'],'--preview-run-id',state['preview_run_id'],
        *[value for stage in ('integration','candidate','benchmark','preview')
          for value in ('--'+stage+'-run-attempt',state[stage+'_run_attempt'])]])
    run(['python','tools/release_contract/promotion.py',*common,'--automatic'])
    try:
        run(['python','tools/release_contract/pages.py','promote',*common,'--automatic',
            '--account',os.environ['ATLAS_ACCOUNT'],'--project',os.environ['ATLAS_PROJECT'],'--head',os.environ['GITHUB_SHA']])
    except ContractError:
        try: run(['python','tools/hosted/rollback.py'])
        except ContractError: pass  # Failed eligibility never authorizes an unsafe restore.
        raise
    shutil.copyfile(ROOT/'reports/pages-deployment.json',ROOT/'.atlas-private/production-deployment.json')

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation',choices=('context','intake','candidate','preview','promotion','dispatch-benchmarks','native-gate','benchmark-case','benchmark-resolve','benchmark-join','cleanup-private'))
    parser.add_argument('--kind',choices=STAGES)
    parser.add_argument('--upstream-run-id',type=int)
    parser.add_argument('--scenario',choices=('cold_full','warm_unchanged','warm_changed','clock_advance','withdrawal'))
    parser.add_argument('--sample',type=int,choices=(1,2,3))
    args=parser.parse_args()
    try:
        if args.operation=='context': context(args.kind,args.upstream_run_id)
        elif args.operation=='intake':
            update_context('intake');run(['python','tools/hosted/source_intake.py'])
        elif args.operation=='benchmark-case':
            if args.scenario is None or args.sample is None: raise ContractError('benchmark case identity required')
            benchmark_case(args.scenario,args.sample)
        else: globals()[args.operation.replace('-','_')]()
        print('Trusted production stage completed')
    except (ContractError,OSError,ValueError,KeyError,subprocess.SubprocessError):
        print('Production stage failed; source details withheld from public logs',file=sys.stderr)
        raise SystemExit(1)

if __name__=='__main__': main()
