#!/usr/bin/env python3
"""Local negative tests for plan/evidence checking; never native passes."""
import copy,json,unittest
from pathlib import Path
from race_manifest import plan,check_plan,check_native_trace
class OracleTests(unittest.TestCase):
    def trace(self):
        p=plan();events=[]
        for i,(peer,event,decision) in enumerate([('api-1','commit',None),('svs-1','ready-get',None),('svs-1','decision','Unauthenticated'),('svs-2','snapshot',None),('svs-2','decision','Unauthenticated')]):
            events.append(dict(sequence=i,peer=peer,event=event,decision=decision,sql=0,control=0,hints=0,usable=False))
        return dict(case='race-0000',peers={s:dict(pid=i+1,boot=f'local-fixture-{i}',verified_identity=True) for i,s in enumerate(p['required_replicas'])},events=events,invalidating_commit=0,measurements=dict(lock_wait_ms=1,reader_p99_ms=2,writer_p99_ms=3))
    def test_complete_plan(self):
        p=plan();check_plan(p);self.assertEqual(1000,len(p['paired_schedules']))
        self.assertTrue(all(s['execution']=='NotRun' for s in p['paired_schedules']+p['fault_schedules']))
        disk=Path(__file__).resolve().parents[2]/'docs/session-validation/SVS13_NATIVE_RACE_MATRIX.json'
        self.assertEqual(p,json.loads(disk.read_text()))
    def test_non_active_after_commit(self):check_native_trace(self.trace())
    def test_negative_evidence(self):
        for fault in ['active','missing-peer','same-process','unverified','missing-reader','missing-read','sql-on-hit','hint-on-hit','sequence','secret','nan','fabricated-commit']:
            with self.subTest(fault=fault):
                r=self.trace()
                if fault=='active':r['events'][2]['decision']='Active'
                elif fault=='missing-peer':r['peers'].pop('api-2')
                elif fault=='same-process':r['peers']['api-2']['pid']=1
                elif fault=='unverified':r['peers']['svs-1']['verified_identity']=False
                elif fault=='missing-reader':r['events']=r['events'][:3]
                elif fault=='missing-read':r['events'].pop(1)
                elif fault=='sql-on-hit':r['events'][2].update(usable=True,sql=1)
                elif fault=='hint-on-hit':r['events'][2].update(usable=True,hints=1)
                elif fault=='sequence':r['events'][2]['sequence']=1
                elif fault=='secret':r['events'][2]['token']='fixture-canary'
                elif fault=='nan':r['measurements']['lock_wait_ms']=float('nan')
                else:r['invalidating_commit']=900
                with self.assertRaises(AssertionError):check_native_trace(r)
    def test_plan_cannot_claim_execution(self):
        p=copy.deepcopy(plan());p['paired_schedules'][0]['execution']='Passed'
        with self.assertRaises(AssertionError):check_plan(p)
if __name__=='__main__':unittest.main()
