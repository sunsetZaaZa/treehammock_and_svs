// Built-in Node HTTP deadline and fresh Bruno evidence; no shell evaluation.
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import https from 'node:https';
import crypto from 'node:crypto';
import {performance} from 'node:perf_hooks';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

export async function ready(base, total=60000, attempt=2000) {
  const url=new URL('/health/ready',base);
  if(!['http:','https:'].includes(url.protocol)||url.username||url.password)throw new Error('Invalid readiness endpoint');
  if(!Number.isInteger(total)||total<1||total>120000||!Number.isInteger(attempt)||attempt<1||attempt>total)throw new Error('Invalid readiness budget');
  const deadline=performance.now()+total;
  while(performance.now()<deadline) {
    const left=deadline-performance.now();
    const passed=await new Promise(resolve=>{
      let done=false, response, request;
      const finish=value=>{if(done)return;done=true;clearTimeout(timer);response?.destroy();request?.destroy();resolve(value);};
      const timer=setTimeout(()=>finish(false),Math.min(attempt,left));
      try {
        request=(url.protocol==='https:'?https:http).get(url, res=>{
          response=res;let bytes=0;
          res.on('data',chunk=>{bytes+=chunk.length;if(bytes>65536)finish(false);});
          res.on('end',()=>finish(res.statusCode===200&&performance.now()<deadline));
          res.on('error',()=>finish(false));res.on('aborted',()=>finish(false));
        });
        request.on('error',()=>finish(false));
      } catch {finish(false);}
    });
    if(passed)return;
    await new Promise(resolve=>setTimeout(resolve,Math.max(0,Math.min(250,deadline-performance.now()))));
  }
  throw new Error('Readiness deadline expired');
}
export function expectedTests(collection) {
  const expected=[];
  for(const file of ['health/live.bru','health/ready.bru']) {
    const text=fs.readFileSync(path.join(collection,file),'utf8');
    const names=[...text.matchAll(/\btest\(\s*"([^"\\]+)"\s*,/g)].map(match=>match[1]);
    if(names.length!==2)throw new Error('Unexpected HTTP collection discovery');expected.push(...names);
  }
  if(new Set(expected).size!==expected.length)throw new Error('Duplicate expected HTTP tests');return expected;
}
export function validateReport(reportFile,expected) {
  const info=fs.lstatSync(reportFile);if(!info.isFile()||info.isSymbolicLink()||info.size>4000000)throw new Error('Invalid result file');
  const value=JSON.parse(fs.readFileSync(reportFile,'utf8'));const tests=[];
  function walk(item) {
    if(!item||typeof item!=='object')return;
    if(Object.hasOwn(item,'testResults')) {
      if(!Array.isArray(item.testResults))throw new Error('Invalid test result list');tests.push(...item.testResults);
    }
    for(const [key,child] of Object.entries(item))if(key!=='testResults')walk(child);
  }
  walk(value);
  if(tests.length!==expected.length||tests.some(t=>t?.status!=='pass'||!expected.includes(t.description))||new Set(tests.map(t=>t.description)).size!==expected.length)throw new Error('Missing, failed, skipped, duplicate or unexpected HTTP tests');
  // Bruno request/assertion failures must also remain failures even with passing tests.
  function failures(item) {
    if(!item||typeof item!=='object')return;
    for(const [key,child] of Object.entries(item)) {
      if(['failedRequests','failedTests','failedAssertions','skippedRequests'].includes(key)&&child!==0)throw new Error('Nonpassing HTTP summary');
      if(key==='assertionResults'&&(!Array.isArray(child)||child.some(x=>x.status!=='pass')))throw new Error('Failed HTTP assertion');
      failures(child);
    }
  }
  failures(value);return tests.length;
}
export async function run(lane,collection,reportRoot,base) {
  if(!['direct','proxy'].includes(lane))throw new Error('Unknown HTTP lane');
  fs.mkdirSync(reportRoot,{recursive:true});
  const runId=crypto.randomUUID(),folder=path.join(reportRoot,'http-'+lane+'-'+runId);fs.mkdirSync(folder);
  const stateFile=path.join(folder,'run.json');let stage='collection',exit=2;
  const state=status=>fs.writeFileSync(stateFile,JSON.stringify({schema_version:1,run_id:runId,lane,status,stage,exit_code:status==='Passed'?0:exit})+'\n');
  state('Running');
  const command=(tool,args,timeout)=>{
    const result=spawnSync(tool,args,{cwd:collection,stdio:'inherit',timeout,killSignal:'SIGKILL'});
    if(result.error||result.status!==0){exit=result.error?.code==='ETIMEDOUT'?124:(result.status??127);throw new Error('Native stage failed');}
  };
  try {
    JSON.parse(fs.readFileSync(path.join(collection,'bruno.json'),'utf8'));
    fs.accessSync(path.join(collection,'environments/docker-'+lane+'.bru'));
    const expected=expectedTests(collection);
    stage='readiness';state('Running');await ready(base,Number(process.env.TREEHAMMOCK_COMPOSE_READY_TIMEOUT_MS??60000),Number(process.env.TREEHAMMOCK_COMPOSE_ATTEMPT_TIMEOUT_MS??2000));
    stage='install';state('Running');command('npm',['install','--prefix',path.join(folder,'tool'),'--no-audit','--no-fund','@usebruno/cli'],120000);
    const executable=path.join(folder,'tool/node_modules/.bin/bru');
    const packageFile=path.join(folder,'tool/node_modules/@usebruno/cli/package.json');
    const cliVersion=fs.existsSync(packageFile)?JSON.parse(fs.readFileSync(packageFile,'utf8')).version:'controlled-or-unavailable';
    const report=path.join(folder,'results.json');if(fs.existsSync(report))throw new Error('Preexisting result');
    stage='tests';state('Running');command(executable,['run','-r','--env-file','environments/docker-'+lane+'.bru','--env-var','baseUrl='+base,'--bail','--reporter-json',report,'--reporter-skip-all-headers','--reporter-skip-body'],180000);
    stage='result-validation';state('Running');const count=validateReport(report,expected);
    fs.writeFileSync(path.join(folder,'proof.json'),JSON.stringify({run_id:runId,node_version:process.version,bruno_version:cliVersion,executed_tests:count,result_sha256:crypto.createHash('sha256').update(fs.readFileSync(report)).digest('hex')})+'\n');
    state('Passed');return 0;
  } catch {try{state('Failed');}catch{}console.error('Compose HTTP proof failed at '+stage+' (exit '+exit+').');return exit;}
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  const [lane,collection,reportRoot]=process.argv.slice(2);
  try{process.exitCode=await run(lane,collection,reportRoot,process.env.TREEHAMMOCK_BASE_URL);}
  catch{console.error('Compose HTTP proof prerequisites failed.');process.exitCode=2;}
}
