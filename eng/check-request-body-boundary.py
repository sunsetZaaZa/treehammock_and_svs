#!/usr/bin/env python3
"""COR23F source-budget/order checks; supplemental, never protocol/runtime qualification."""
import argparse
import json
import re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

def require(valid,message):
    if not valid: raise ValueError(message)

def validate(root):
    read=lambda path:(root/path).read_text()
    program=re.sub(r'//[^\n]*','',read('Program.cs'));gate='app.UseMiddleware<RequestBodyMiddleware>();'
    require(program.count(gate)==1 and 'UseRequestDecompression' not in program and 'AddRequestDecompression' not in program,'One bounded decoder replaces the lazy framework decoder')
    require(program.index('app.UseMiddleware<SecurityResponseCacheMiddleware>();')<program.index('app.UseMiddleware<HttpExceptionFallbackMiddleware>();')<program.index(gate)<program.index('app.UseMiddleware<treehammock.Rigging.Operations.SecurityOperationMiddleware>();'),'Privacy/fallback/body validation must precede operation admission')
    require('options.Limits.MaxRequestBodySize = body.EncodedBytes + 1L;' in program and '.WithMetadata(app.Services.GetRequiredService<RequestBodyPolicy>().Limits)' in program,'Transport probe bound and declared controller metadata')
    boundary=read('Rigging/Hosting/RequestBodyMiddleware.cs')
    for token in ['originalLength > limits.EncodedBytes','new byte[limits.EncodedBytes + 1]','new byte[limits.DecodedBytes + 1]','length == encoded.Length','length > limits.DecodedBytes','policy.TryEnter()','deadline.CancelAfter(limits.ReadMilliseconds)','http.RequestAborted.ThrowIfCancellationRequested();','catch (InvalidDataException)','catch (RequestBodyFailure failure) when (!http.Response.HasStarted && !http.RequestAborted.IsCancellationRequested)','SecurityResponseCacheMiddleware.Apply(http.Response);','validatedBody?.Dispose();','if (entered) policy.Exit();','http.Request.Body = originalBody;']:
        require(token in boundary,'Body boundary lacks '+token)
    require(boundary.index('StrictRequestBodyDecoder.DecodeAsync')<boundary.index('http.Request.Body = validatedBody;')<boundary.rindex('await next(http);'),'Decode completes before downstream execution')
    require('catch (IOException)' not in boundary and 'catch (Exception)' not in boundary,'Do not classify unrelated I/O/application failures as compression errors')
    require('values.Count != 1' in boundary and ".Contains(',')" in boundary and '"gzip" or "deflate" or "br"' in boundary,'Single declared encoding policy')
    decoder=read('Rigging/Hosting/StrictRequestBodyDecoder.cs')
    for token in ['Position == Length','source.Position != source.Length','remaining > 256 ? remaining - 256','new ZLibStream(','new DeflateStream(','expectedCrc != Crc32','expectedLength != (uint)written','OperationStatus.Done','consumed != length','written == output.Length','token.ThrowIfCancellationRequested();']:
        require(token in decoder,'Complete, bounded codec contract lacks '+token)
    canonical=read('Rigging/Operations/SecurityOperationMiddleware.cs')
    require('catch (IOException)' not in canonical and 'ValidatedRequestBody' in canonical,'Canonical reader uses validated decoded budget and does not disguise I/O')
    registration=read('Rigging/DependencyInjection/TreehammockServiceCollectionExtensions.cs')
    require('ErrorOnUnknownConfiguration = true' in registration and '.AddOptions<RequestBodySettings>()' in registration and 'services.AddSingleton<RequestBodyPolicy>();' in registration,'Validate startup budgets and share admission capacity')
    policy=read('Rigging/Hosting/RequestBodyPolicy.cs')
    require('_capacity.Wait(0)' in policy and 'RequestBodyPolicyMetadata Limits { get; }' in policy,'No unbounded wait queue or reloadable budget')
    for path in root.glob('appsettings*.json'):
        settings=json.loads(path.read_text())['RequestBodySettings']
        require(settings==dict(EncodedBytes=262144,DecodedBytes=1048576,ConcurrentRequests=16,ReadMilliseconds=5000),'Shipped request contract changed: '+path.name)
    for path,name in [('treehammock.Tests/Integration/BodyHttpTests.cs','Malformed_and_every_truncated_frame'),('treehammock.Tests/Integration/BodyResourceTests.cs','Kestrel_capacity_rejects'),('treehammock.Tests.SqlContracts/Integration/Database/RefreshHttpTests.cs','Cor23F_rejected_refresh_bodies_create_no_operation_or_session_write')]:
        require(name in read(path),'Required native regression absent: '+name)
    return dict(status='SourceContractsConsistent',qualification='NotRun',default_encoded_bytes=262144,default_decoded_bytes=1048576,concurrent_buffered_requests=16,read_deadline_milliseconds=5000,owned_buffer_upper_bound_bytes=16*(262144+1048576+2),native_required=['fast','sql-harness','sql','system','COR22 resource qualification'])

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,default=ROOT);args=parser.parse_args()
    try:print(json.dumps(validate(args.root),indent=2));return 0
    except (ValueError,OSError,KeyError) as error:print(str(error));return 1
if __name__=='__main__':raise SystemExit(main())
