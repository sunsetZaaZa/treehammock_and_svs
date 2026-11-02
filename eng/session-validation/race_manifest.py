"""Closed SVS-13 native execution plan and trace oracle, never an execution driver."""
MUTATIONS=['second-login','refresh','family','session-stamp','account-stamp','logout-current','logout-all','revocation','lock','verification','deletion','capability','calendar']
MODES=['mutation-first','refill-first','rollback','unknown-commit','writer-only-partition','cancelled-late-CAS']
FAULTS=['stale-raw-CAS','cache-eviction','cache-incarnation-change','epoch-replay','fresh-epoch-recovery','cancelled-read-cleanup','full-response-drain','missing-peer','unreachable-peer','full-reader-writer-isolation']
def plan():
    return dict(pr='SVS-13',status='NotRun',kind='Native target plan; rows are not discovered or executed tests',
        fleet_protocol='authority-fleet.v2',sql_policy_version=2,
        required_replicas=['api-1','api-2','svs-1','svs-2'],
        prerequisites=['Explicit owned disposable Yugabyte and pinned Dragonfly','Exact THS-12C application owners issue and mutate actual sessions','Separate API and SVS processes with verified identities/TLS','Separate foreground/background SQL and cache identities','All inventory peers retained, including unreachable peers'],
        paired_schedules=[dict(id=f'race-{n:04d}',mutation=MUTATIONS[n%13],mode=MODES[(n//13)%6],writer=f'api-{1+n%2}',readers=['svs-1','svs-2'],execution='NotRun') for n in range(1000)],
        fault_schedules=[dict(id=f'fault-{n:02d}',fault=f,execution='NotRun') for n,f in enumerate(FAULTS)],
        oracle='No Active if an invalidating known commit precedes Ready GET or fallback snapshot; missing coherent evidence denies; usable hits perform zero SQL/control/hint calls',
        required_measurements=['Transaction commit and Ready GET/DB snapshot linearization points','Actual SQL serializable conflicts/lock waits','Reader p99 and writer contention p99','Per-replica PID, boot ID, verified role, runtime/source/policy hashes','Raw provider completion, lease release and response completion order','No raw token, signing key or credential binding in traces'],
        grant_rights=False,release_ready=False)
def check_plan(p):
    assert p==plan(),'Manifest drift or native result asserted inside a plan'
def check_native_trace(report):
    """Review exported evidence. Passing this oracle is not target attestation.

    Native driver must collect server-side ordered observations, not correlate
    unsynchronized wall clocks. No acceptance is inferred from local counters.
    """
    assert set(report)=={'case','peers','events','invalidating_commit','measurements'}
    assert report['case'] in {x['id'] for x in plan()['paired_schedules']}
    peers=report['peers'];assert set(peers)==set(plan()['required_replicas'])
    assert len({p['pid'] for p in peers.values()})==4
    for peer in peers.values():
        assert set(peer)=={'pid','boot','verified_identity'} and type(peer['pid']) is int and peer['pid']>0
        assert isinstance(peer['boot'],str) and peer['boot'] and peer['verified_identity'] is True
    events=report['events'];assert events and all(set(e)=={'sequence','peer','event','decision','sql','control','hints','usable'} for e in events)
    order=[e['sequence'] for e in events];assert order==sorted(set(order))
    commit=report['invalidating_commit'];assert commit is None or type(commit) is int and commit in order
    if commit is not None:assert any(e['sequence']==commit and e['event']=='commit' and e['peer'].startswith('api-') for e in events)
    seen=set()
    for e in events:
        assert e['peer'] in peers and e['event'] in {'commit','ready-get','snapshot','decision','raw-complete','lease-release','response-complete'}
        assert all(type(e[k]) is int and e[k]>=0 for k in ['sql','control','hints']) and type(e['usable']) is bool
        if e['event']=='decision':
            seen.add(e['peer']);assert e['peer'].startswith('svs-')
            assert e['decision'] in {'Active','Forbidden','Unauthenticated','Unavailable'}
            reads=[r for r in events if r['peer']==e['peer'] and r['event'] in {'ready-get','snapshot'} and r['sequence']<e['sequence']]
            assert reads,'Decision lacks its actual observation point'
            if commit is not None and commit<reads[-1]['sequence']:assert e['decision']!='Active'
            if e['usable']:assert e['sql']==e['control']==e['hints']==0
    assert seen=={'svs-1','svs-2'}
    assert set(report['measurements'])=={'lock_wait_ms','reader_p99_ms','writer_p99_ms'}
    assert all(type(v) in {int,float} and v>=0 and __import__('math').isfinite(v) for v in report['measurements'].values())
