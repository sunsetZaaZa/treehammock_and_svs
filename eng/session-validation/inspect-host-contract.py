#!/usr/bin/env python3
"""Offline source/resource checks only; not permission, transport or target qualification."""
from pathlib import Path
import hashlib,json
R=Path(__file__).resolve().parents[2]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
policy=R/'deploy/session-validation/treehammock-validator-policy.json';spec=json.loads((R/'deploy/session-validation/validator-privilege-audit-specification.json').read_text());p=json.loads(policy.read_text())
assert sha(policy)==spec['policy_sha256']
assert p['functions']['ths_database_role_safe']['body_sha256']==spec['helper_source_sha256']
assert sha(R/'tests/Treehammock.SessionValidation.StorageTests/Fixtures/validator-helper-source.txt')==spec['helper_source_sha256']
assert sha(policy)==sha(R/'docs/session-validation/upstream/THS-12A/THS10_DATABASE_POLICY.json')
host=(R/'src/Treehammock.SessionValidation.Api/SvsHost.cs').read_text();identity=(R/'src/Treehammock.SessionValidation.Storage/TreehammockIdentityAuditor.cs').read_text()
assert 'HttpProtocols.Http2' in host and 'ClientCertificateMode.RequireCertificate' in host and 'builder.Configuration.Sources.Clear()' in host
assert 'CreateTreehammockValidator' in (R/'src/Treehammock.SessionValidation.Api/HostResources.cs').read_text()
assert identity.index('TreehammockIdentityPolicy.Preflight')<identity.index('select public.ths_database_role_safe')
assert all(text not in host for text in ['ForQualification','MapControllers','UseCertificateForwarding','AddSwagger'])
assert 'MapGrpcService<ValidationService>()' in host and 'AddGrpc' in host
assert host.index('AddGrpc') < host.index('builder.Build()')
assert 'context.Request.Headers.TryGetValue("grpc-encoding"' in host and 'encoding[0] != "identity"' in host
assert host.index('context.Request.Headers.TryGetValue("grpc-encoding"') < host.index('var requests = context.RequestServices')
assert 'ContractCodec.DecodeRequestBinary' in (R/'src/Treehammock.SessionValidation.Api/ValidationService.cs').read_text()
print(json.dumps(dict(status='PASS',policy_and_helper_fingerprints='Exact reviewed THS12A resource/fixture',host='Private HTTP2/pinned mTLS composition',scope='Offline source checks only; runtime and native evidence separate',native_cases_executed=0),indent=2))
