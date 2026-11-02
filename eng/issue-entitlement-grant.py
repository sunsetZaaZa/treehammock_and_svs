#!/usr/bin/env python3
"""Restricted operator grant issuer. Reads a reviewed approval file, never account credentials."""
import argparse, datetime, json, os, subprocess, sys, uuid
from pathlib import Path

def literal(value):
    if value is None: return 'null'
    return "'" + str(value).replace("'", "''") + "'"

def timestamp(value):
    if value is None: return None
    if not isinstance(value,str): raise ValueError('Approval boundary must be a UTC timestamp string')
    result = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.tzinfo is None or result.utcoffset() != datetime.timedelta(0):
        raise ValueError('Approval boundaries require explicit UTC timestamps')
    return result.isoformat()

def approval_sql(approval):
    expected = {'grantId','accountId','accountStamp','catalog','tier','term','cadence','approvedStart','authorizedEnd','maxCycles','redeemBefore','issuerReference','startAnchor','deniedCapabilities'}
    if set(approval) != expected: raise ValueError('Exact reviewed approval fields are required')
    for key in ['grantId','accountId','accountStamp']:
        approval[key] = str(uuid.UUID(approval[key]))
        if uuid.UUID(approval[key]).int == 0: raise ValueError('Empty authority identity')
    for key, low, high in [('tier',1,2),('term',1,11),('cadence',0,1),('maxCycles',1,1000)]:
        if type(approval[key]) is not int or not low <= approval[key] <= high: raise ValueError('Invalid approval ' + key)
    if approval['term'] in (4,5): raise ValueError('Ambiguous term label is unsupported')
    if approval['cadence'] == 0 and approval['maxCycles'] != 1: raise ValueError('No-repeat grants have one cycle')
    if approval['term'] == 11 and (approval['cadence'] != 0 or approval['maxCycles'] != 1): raise ValueError('Indefinite grants do not renew')
    if approval['startAnchor'] not in ('redemption','approved-boundary'): raise ValueError('Explicit start anchor is required')
    if (approval['approvedStart'] is None) != (approval['startAnchor'] == 'redemption'): raise ValueError('Approved boundary and anchor disagree')
    denies=approval['deniedCapabilities']
    if not isinstance(denies,list) or len(denies)>2 or any(type(c) is not str or c not in ('account.read','account.manage') for c in denies): raise ValueError('Unsupported capability denial')
    if approval['catalog'] != 'treehammock-v1': raise ValueError('Unknown capability catalog')
    if not isinstance(approval['issuerReference'],str) or not 1 <= len(approval['issuerReference'].strip()) <= 256: raise ValueError('Reviewed issuer reference is required')
    values = [literal(approval[k])+'::uuid' for k in ['grantId','accountId','accountStamp']]
    values += [literal(approval['catalog'])]
    values += [str(approval[k])+'::smallint' for k in ['tier','term','cadence']]
    values += [literal(timestamp(approval[k]))+'::timestamptz' for k in ['approvedStart','authorizedEnd']]
    values += [str(approval['maxCycles'])+'::integer',literal(timestamp(approval['redeemBefore']))+'::timestamptz',literal(approval['issuerReference'])]
    values += [literal(approval['startAnchor']), 'array['+','.join(literal(c) for c in sorted(set(denies)))+']::text[]']
    # A denial aborts the command with no domain/audit changes. The approval, audit and commit are one transaction.
    arguments=','.join(values)
    delimiter='$issuer_'+uuid.uuid4().hex+'$'
    while delimiter in arguments: delimiter='$issuer_'+uuid.uuid4().hex+'$'
    return "begin;\nset local standard_conforming_strings=on;\ndo "+delimiter+" declare outcome record; begin select * into outcome from cor19_issue_grant("+arguments+"); if not outcome.result then raise exception '%',outcome.code; end if; end "+delimiter+";\ncommit;\n"

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('approval',type=Path);args=parser.parse_args()
    connection=os.environ.get('COR19_ISSUER_DATABASE_URL')
    if not connection: parser.error('COR19_ISSUER_DATABASE_URL must identify the separately provisioned issuer login')
    try:
        approval=json.loads(args.approval.read_text())
        sql=approval_sql(approval)
    except (ValueError,TypeError,KeyError) as error: parser.error(str(error))
    env=os.environ.copy();env['PGDATABASE']=connection;env.pop('COR19_ISSUER_DATABASE_URL',None)
    try: result=subprocess.run(['psql','-X','-q','-v','ON_ERROR_STOP=1'],input=sql,text=True,env=env,capture_output=True)
    except FileNotFoundError: parser.error('psql is required for the restricted operator command')
    if result.returncode:
        # Provider/connection diagnostics may contain credentials. Emit only the controlled operator outcome.
        print('Grant issuance failed; inspect restricted database audit/connection diagnostics.',file=sys.stderr);return 1
    print('ENTITLEMENT_GRANT_ISSUED '+str(approval['grantId']));return 0

if __name__=='__main__': sys.exit(main())
