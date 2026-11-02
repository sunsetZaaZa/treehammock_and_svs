#!/usr/bin/env python3
"""COR23AA source contract; compiled/HTTP/supported-host qualification remains separate."""
import argparse,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def require(value,message):
 if not value:raise ValueError(message)
def validate(root):
 helper=(root/'eng/test-ownership.py').read_text();proof=(root/'eng/host-system-proof.py').read_text()
 for token in ['owner.proof.prepare(env)',"[executable,str(assembly),'--urls'",'lifecycle.proof.tick()','not lifecycle.proof.completed',"operation=='api-proof'","operation=='api-ready'",'hostproof.startup_seconds(environment)']:
  require(token in helper,'Missing owned host launch/proof monitoring: '+token)
 require("'run','--project','treehammock.csproj'" not in helper,'Host launch must use the exact DLL')
 for token in ["binary.name+'.proof-id'",'sha(copy)==sha(app)','System test target differs',"self.owner.processes.identity(value['pid'])",'Proxy reaches another application','Backing state is not healthy','startup-budget','endpoint-unavailable','validate_trx(trx,expected_tests(root))',"byname['treehammock']['mvid']==self.runtime['mvid']",'transport.shutdown(socket.SHUT_RDWR)']:
  require(token in proof,'Missing binary/endpoint/result/budget proof: '+token)
 for ext in ['sh','ps1']:
  source=(root/'eng'/('docker-host-system-stack-tests.'+ext)).read_text()
  for token in ['api-ready','api-proof','http://127.0.0.1:8080','treehammock.csproj']:
   require(token in source,'Host wrapper omits current proof: '+token)
 controller=(root/'Controllers/SystemTestIdentityController.cs').read_text()
 for token in ['if (!capability.InspectionEnabled) return NotFound();','capability.Authorizes(Request)','NoStore = true','identity.Value is null ? NotFound()']:
  require(token in controller,'Identity access/cache boundary missing: '+token)
 require('typeof(SystemTestIdentityController)' in (root/'Rigging/Hosting/SystemTestControllerFeatureProvider.cs').read_text(),'Identity route escapes disabled-host discovery')
 identity=(root/'Rigging/Hosting/HostSystemTestIdentity.cs').read_text()
 for token in ['!capability.InspectionEnabled','TreehammockProofRunId','configurationName != "Release"','actualHash != hash','ModuleVersionId','Environment.ProcessId']:
  require(token in identity,'Loaded identity startup guard missing: '+token)
 require('HostSystemTestIdentity.FromConfiguration(configuration, systemTestCapability)' in (root/'Rigging/DependencyInjection/TreehammockServiceCollectionExtensions.cs').read_text(),'Identity must be validated at actual startup')
 return dict(status='SourceContractsConsistent',qualification='NotRun',scope='Exact loaded DLL/build/process/direct/proxy/backing readiness, monotonic startup and complete fresh System proof')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,default=ROOT);a=p.parse_args()
 try:print(json.dumps(validate(a.root),indent=2))
 except (OSError,ValueError) as e:print(str(e));raise SystemExit(1)
