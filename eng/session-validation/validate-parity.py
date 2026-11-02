#!/usr/bin/env python3
"""SVS-12 real issuer, cross-target goldens, normal host and exact peer middleware."""
import argparse,json,hashlib,os,subprocess,sys,tempfile,time,zipfile,shutil,xml.etree.ElementTree as ET
from pathlib import Path
R=Path(__file__).resolve().parents[2]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--dotnet',required=True);p.add_argument('--packages',required=True,type=Path);p.add_argument('--source',action='append',default=[]);p.add_argument('--evidence-dir',required=True,type=Path);p.add_argument('--baseline-archive',required=True,type=Path);p.add_argument('--peer-archive',required=True,type=Path);a=p.parse_args();e=a.evidence_dir.resolve();e.mkdir(parents=True,exist_ok=True);env=os.environ.copy();env.update(DOTNET_ROOT=str(Path(a.dotnet).resolve().parent),NUGET_PACKAGES=str(a.packages.resolve()),MSBUILDDISABLENODEREUSE='1',SVS12_EVIDENCE_DIRECTORY=str(e/'observations'))
 assert sha(a.baseline_archive)=='f80eb2feea073a1c6dba9049cce4b28c913b0021c71890cc859a29b62d582aa2'
 assert sha(a.peer_archive)=='364de19c8a5c65d82e79bbb22f745effeb59281d97a2dd10ae4b8e1d3a5d41b0'
 def production(n):return (n.startswith('src/') or n.startswith(('Controllers/','DataLayer/','Entities/','Models/','Repos/','Rigging/','RiggingSupport/','Services/')) or n in ['Program.cs','treehammock.csproj','Directory.Build.props','Directory.Build.targets','Directory.Packages.props']) and not {'bin','obj'}.intersection(Path(n).parts)
 with zipfile.ZipFile(a.baseline_archive) as z:
  original=json.loads(z.read('CURRENT_SOURCE_SHA256.json'));runtime={n:h for n,h in original.items() if production(n)}
 assert runtime and all((R/n).is_file() and sha(R/n)==h for n,h in runtime.items()),'Unexpected production drift'
 assert {p.relative_to(R).as_posix() for p in R.rglob('*') if p.is_file() and production(p.relative_to(R).as_posix())}==set(runtime),'Unexpected production addition'
 (e/'PRODUCTION_SOURCE_PRESERVATION.json').write_text(json.dumps({'unchanged_files':runtime,'status':'ByteIdenticalToSVS11'},indent=2)+'\n')
 commands=[]
 def run(label,args,cwd=R/'tests'):
  start=time.monotonic()
  with (e/(label+'.log')).open('w') as f:r=subprocess.run(args,env=env,cwd=cwd,stdout=f,stderr=subprocess.STDOUT,timeout=1800)
  commands.append(dict(name=label,argv=args,exit_code=r.returncode,seconds=round(time.monotonic()-start,3)));(e/'COMMANDS.json').write_text(json.dumps(commands,indent=2)+'\n');print(label,r.returncode,flush=True)
  if r.returncode:raise SystemExit('Failed '+str(e/(label+'.log')))
 def build(label,project,cwd=R/'tests'):
  args=[a.dotnet,'restore',str(project),'--locked-mode','--disable-parallel','-m:1','-nr:false','-p:NuGetAudit=false']
  for s in a.source:args+=['--source',s]
  run(label+'-restore',args,cwd);run(label+'-build',[a.dotnet,'build',str(project),'-c','Release','--no-restore','-m:1','-nr:false','-p:UseSharedCompilation=false'],cwd)
 build('current-issuer',R/'treehammock.Tests/treehammock.Tests.csproj');tokens=e/'current-issued-tokens.json';env['SVS12_EXPORT_TOKENS']=str(tokens)
 run('current-issuer',[a.dotnet,str(R/'treehammock.Tests/bin/Release/net8.0/treehammock.Tests.dll'),'-class','*Svs12CurrentIssuerTests','-maxThreads','1','-xml',str(e/'current-issuer.xml')]);assert tokens.exists();env.pop('SVS12_EXPORT_TOKENS');env['SVS12_ISSUED_TOKENS_PATH']=str(tokens)
 args=[sys.executable,str(R/'eng/session-validation/validate-local-refill.py'),'--dotnet',a.dotnet,'--packages',str(a.packages.resolve()),'--evidence-dir',str(e/'regressions'),'--peer-archive',str(a.peer_archive.resolve())]
 for s in a.source:args+=['--source',s]
 run('svs11-regressions-and-new-goldens',args)
 with tempfile.TemporaryDirectory(prefix='svs12-peer-') as tmp:
  with zipfile.ZipFile(a.peer_archive) as z:assert z.testzip() is None;z.extractall(tmp)
  peer=Path(tmp)/'source/treehammock-main';original={str(p.relative_to(peer)):sha(p) for p in peer.rglob('*') if p.is_file()};tests=peer/'treehammock.Tests';overlay=[]
  for src,name in [(R/'tests/Treehammock.SessionValidation.ContractTests/TreehammockParityFixtures.cs','Svs12GoldenFixtures.cs'),(R/'tests/Treehammock.SessionValidation.StorageTests/ParityHarness.cs','ParityHarness.cs'),(R/'treehammock.Tests/Unit/CurrentIssuerTests.cs','CurrentIssuerTests.cs'),(R/'tests/Treehammock.SessionValidation.ContractTests/PeerOverlay/MiddlewareGoldenTests.cs.txt','Svs12MiddlewareGoldenTests.cs')]:
   dst=tests/'Unit'/name;assert not dst.exists();shutil.copyfile(src,dst);overlay.append(dict(source=str(src.relative_to(R)),destination=str(dst.relative_to(peer)),sha256=sha(dst)))
  shutil.copytree(R/'tests/Treehammock.SessionValidation.ContractTests/Fixtures/GoldenSessions',tests/'Fixtures/GoldenSessions')
  # Test-only content copying; all original production and lock bytes remain fixed.
  project=tests/'treehammock.Tests.csproj';before=sha(project);project.write_text(project.read_text().replace('</Project>','<ItemGroup><Content Include="Fixtures/GoldenSessions/**" CopyToOutputDirectory="PreserveNewest"/></ItemGroup></Project>'))
  build('peer-overlay',project,peer/'tests')
  run('peer-golden',[a.dotnet,str(tests/'bin/Release/net8.0/treehammock.Tests.dll'),'-class','*Svs12MiddlewareGoldenTests','-class','*Svs12CurrentIssuerTests','-maxThreads','1','-xml',str(e/'peer-golden.xml')],peer/'tests')
  assert all(sha(peer/n)==h for n,h in original.items() if n!='treehammock.Tests/treehammock.Tests.csproj'),'Peer production source altered'
  (e/'PEER_TEST_OVERLAY.json').write_text(json.dumps({'peer_archive_sha256':sha(a.peer_archive),'production_source_and_locks_unchanged':True,'test_project_original_sha256':before,'test_project_overlay_sha256':sha(project),'overlay':overlay,'note':'Only added test source/data and test content-copying item; no peer production or original fixture replaced.'},indent=2)+'\n')
 # Cross-target equality checks observations, not just aggregate green counts.
 observations={}
 for f in (e/'observations').glob('*.json'):
  name=f.name.split('-.NET_')[0];observations.setdefault(name,[]).append((f.name,json.loads(f.read_text())))
 required=[f'{prefix}-{c["id"]}' for c in json.loads((R/'tests/Treehammock.SessionValidation.ContractTests/Fixtures/GoldenSessions/session-cases.json').read_text())['cases'] for prefix in ['policy','sdk']]
 required += [f'coordinator-{c["id"]}-{warm}' for c in json.loads((R/'tests/Treehammock.SessionValidation.ContractTests/Fixtures/GoldenSessions/session-cases.json').read_text())['cases'] for warm in [False,True]]
 required += [f'wire-{kind}-{fmt}' for kind in ['valid-request','valid-reply','request-unknown','request-duplicate','missing-credential','version','unknown-action','reply-unknown','reply-duplicate','subject-on-refusal','wrong-request','wrong-policy','generation-zero','generation-overflow','protocol','uuid-size','validity-equality','validity-after-deadline','unknown-decision','missing-decision-id'] for fmt in [False,True]]
 pairs=[]
 for name in required:
  rows=observations[name];assert len(rows)==2,(name,'Missing framework observation');assert rows[0][1]==rows[1][1],(name,'Framework decision drift');pairs.append({'case':name,'reports':[f for f,v in rows]})
 (e/'CROSS_TARGET_PARITY.json').write_text(json.dumps({'status':'Passed','equal_observation_pairs':len(pairs),'pairs':pairs},indent=2)+'\n')
 baseline=json.loads((e/'regressions/VALIDATION.json').read_text());extra=[]
 for name in ['current-issuer.xml','peer-golden.xml']:
  a2=ET.parse(e/name).getroot().find('assembly');row={k:int(a2.get(k,'0')) for k in ['total','passed','failed','errors','skipped','not-run']};assert row['total'] and not any(row[k] for k in ['failed','errors','skipped','not-run']);extra.append(dict(report=name,sha256=sha(e/name),**row))
 summary=dict(pr='SVS-12',status='ImplementedCrossTargetGoldenParityPendingNativeAcceptance',total_test_executions=baseline['total_test_executions']+sum(x['passed'] for x in extra),regressions=baseline,extra_reports=extra,cross_target_observation_pairs=len(pairs),corpus_cases=60,production_files_unchanged=len(runtime),native_cases_discovered=baseline['native_cases_discovered'],native_cases_executed=0,build_errors=0,release_ready=False,grant_rights=False,next_pr='SVS-13',F02='OpenNativeAdjudicationRequired',scope='Issued by actual current source; .NET8/10 local data parity; actual loopback TLS SDK/host; exact THS12C validator/middleware with storage doubles; no live target qualification')
 summary['build_warning_counts']={p.relative_to(e).as_posix():int(__import__('re').findall(r'(\d+) Warning\(s\)',p.read_text())[-1]) for p in e.rglob('*-build.log')}
 summary['new_svs_project_warnings']=sum(n for k,n in summary['build_warning_counts'].items() if 'Treehammock.SessionValidation.' in k)
 (e/'VALIDATION.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps({k:v for k,v in summary.items() if k not in ['regressions','extra_reports']},indent=2))
if __name__=='__main__':main()
