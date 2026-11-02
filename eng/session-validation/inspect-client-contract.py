#!/usr/bin/env python3
"""Offline composition assertions only; no native acceptance."""
from pathlib import Path
import json
R=Path(__file__).resolve().parents[2];C=R/'src/Treehammock.SessionValidation.Client';s=(C/'SessionValidatorClient.cs').read_text();t=(C/'GrpcValidationTransport.cs').read_text();a=(R/'src/Treehammock.SessionValidation.Api/ValidationService.cs').read_text()
assert 'ContractCodec.DecodeReplyBinary' in s and 'ContractRules.CheckReply' in s and 'GetElapsedTime' in s and 'pending.ContinueWith' in s and 'CryptographicOperations.ZeroMemory' in s
assert 'svs-deadline-unix-ms' in t and a.index('ContractCodec.DecodeRequestBinary')<a.index('svs-deadline-unix-ms')<a.index('coordinator.ValidateAsync')
assert 'ceiling > clientDeadline.Value' in a and 'if (ceiling < deadline) deadline = ceiling' in a
for x in ['UseProxy=false','AllowAutoRedirect=false','UseCookies=false','CompressionProviders=[]','MaxRetryAttempts=1','DisableResolverServiceConfig=true','ConnectionStream','_connections.EnterAsync'] : assert x in t,x
all_source='\n'.join(p.read_text() for p in C.glob('*.cs'));assert all(x not in all_source for x in ['Npgsql','JwtSecurityTokenHandler','StringSetAsync','ForQualification','Console.Write','ILogger<'])
assert 'Storage' not in (C/'Treehammock.SessionValidation.Client.csproj').read_text()
print(json.dumps(dict(status='PASS',scope='Offline structure only; no native qualification',positive_identity_cache=False,native_executions=0),indent=2))
