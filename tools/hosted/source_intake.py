"""Verify actual active-source intake; publish aggregate evidence only."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from tools.atlas_contracts.config import load_configs
from tools.release_contract.contracts import canonical_bytes, ContractError

SAFE_REASONS=frozenset({'asset_unavailable','schema_or_parser_failed','publication_not_payload_bound',
    'reviewed_fixture_certification_required','publication_metadata_unavailable','publication_expired','content_expired'})

def aggregate(private, expected, clock, catalog_count):
    # Emit controlled aggregate categories only. Never copy a source identity,
    # URL, raw parser error, receipt or normalized record into public evidence.
    current={row['ID'] for row in private['Reconciliation'] if row['State']=='current'}
    if int(datetime.fromisoformat(private['EvaluatedAt'].replace('Z','+00:00')).timestamp())!=clock or private['SourceCount']!=catalog_count:
        raise ContractError('intake report does not bind the requested evaluation')
    counts={}
    for row in private['IntakeDecisions']:
        if row['ID'] in expected and row['State']!='current':
            reason=row['Reason'] if row['Reason'] in SAFE_REASONS else 'other_intake_gate'
            counts[reason]=counts.get(reason,0)+1
    return {'schema_version':1,'scope':'actual-source-intake-not-production-acceptance',
        'evaluated_at':clock,'configured_sources':catalog_count,'active_sources':len(expected),
        'current_sources':len(current),'all_active_current':current==expected and private['CurrentCount']==len(expected),
        'production_eligible':False,'blocked_reason_counts':counts}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report',type=Path,default=ROOT/'reports/source-intake.json')
    args=parser.parse_args()
    configs=load_configs()
    expected={source['id'] for source in configs['sources']['sources'] if source['admission']=='active'}
    if not expected:
        raise ContractError('no reviewed active source inputs')
    clock=int(datetime.now(timezone.utc).timestamp())
    result=subprocess.run(['go','run','./cmd/atlas','intake','-workspace',str(ROOT),'-clock',str(clock)],
        cwd=ROOT,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=35*60,check=False)
    if result.returncode:
        raise ContractError('actual source intake failed; private receipts remain on the runner')
    private=json.loads((ROOT/'.atlas-private/intake-report-v1.json').read_text())
    # A successful process and admission labels do not prove current intake.
    document=aggregate(private,expected,clock,len(configs['sources']['sources']))
    document.update(normalized_state_sha256=sha256((ROOT/'.atlas-private/state-v1.json').read_bytes()).hexdigest(),
        source_catalog_sha256=sha256((ROOT/'configs/sources.yaml').read_bytes()).hexdigest())
    args.report.parent.mkdir(parents=True,exist_ok=True)
    args.report.write_bytes(canonical_bytes(document))
    if not document['all_active_current']:
        print('Actual intake aggregate: '+json.dumps(document['blocked_reason_counts'],sort_keys=True),file=sys.stderr)
        raise ContractError('actual intake did not retain every reviewed active source')
    print(f"Actual full-payload intake passed: {document['current_sources']} reviewed inputs; production acceptance remains separate")

if __name__=='__main__':
    try: main()
    except (ContractError,ValueError,OSError,subprocess.TimeoutExpired):
        print('Actual source-intake verification failed; consult private runner evidence',file=sys.stderr)
        raise SystemExit(1)
