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
from tools.release_contract.contracts import ContractError, canonical_bytes
from tools.release_contract.production import read_private

# Integration now includes intake plus the separately bounded real cold compile.
# This wait is orchestration headroom, not a build/performance threshold.
EXACT_HEAD_WAIT_SECONDS=105*60

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
              'preview':WORKFLOWS['candidate'],'promotion':WORKFLOWS['preview']}[kind]
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
    with open(os.environ['GITHUB_OUTPUT'],'a') as output: output.write(f'upstream_run_id={upstream}\n')
    with open(os.environ['GITHUB_ENV'],'a') as output: output.write(f'ATLAS_UPSTREAM_RUN={upstream}\n')

def update_context(kind):
    path=ROOT/'.atlas-private/workflow-context.json'
    value=json.loads(path.read_text()) if path.exists() else {}
    previous={'intake':'integration','candidate':'intake','preview':'candidate','promotion':'preview'}[kind]
    value[previous+'_run_id']=int(os.environ['ATLAS_UPSTREAM_RUN'])
    value['head_sha']=os.environ['GITHUB_SHA']
    value[kind+'_run_id']=int(os.environ['GITHUB_RUN_ID'])
    path.parent.mkdir(exist_ok=True,mode=0o700);path.write_bytes(canonical_bytes(value))
    return value

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
    update_context('candidate')
    clock=intake_clock();private=ROOT/'.atlas-private'
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
    run(['python','tools/hosted/production-build.py','--atlas-binary','build-private/atlas'])
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
        '--preview-run-id',state['preview_run_id']])
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
    parser.add_argument('operation',choices=('context','intake','candidate','preview','promotion'))
    parser.add_argument('--kind',choices=tuple(WORKFLOWS))
    parser.add_argument('--upstream-run-id',type=int)
    args=parser.parse_args()
    try:
        if args.operation=='context': context(args.kind,args.upstream_run_id)
        elif args.operation=='intake':
            update_context('intake');run(['python','tools/hosted/source_intake.py'])
        else: globals()[args.operation]()
        print('Trusted production stage completed')
    except (ContractError,OSError,ValueError,KeyError,subprocess.SubprocessError):
        print('Production stage failed; source details withheld from public logs',file=sys.stderr)
        raise SystemExit(1)

if __name__=='__main__': main()
