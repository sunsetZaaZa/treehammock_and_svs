#!/usr/bin/env python3
"""COR23E supplemental response privacy/order check, never native HTTP/cache qualification."""
import argparse
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

def require(condition,message):
    if not condition: raise ValueError(message)

def validate(root):
    program=(root/'Program.cs').read_text()
    gate='app.UseMiddleware<SecurityResponseCacheMiddleware>();'
    require(program.count(gate)==1,'Install one early response privacy policy')
    for downstream in ['app.UseMiddleware<HttpExceptionFallbackMiddleware>();','app.UseForwardedHeaders(', 'app.UseHttpsRedirection();','app.UseResponseCompression();', 'app.UseMiddleware<RequestBodyMiddleware>();', 'app.UseMiddleware<treehammock.Rigging.Operations.SecurityOperationMiddleware>();', 'app.UseMiddleware<treehammock.Rigging.Dependencies.DependencyExceptionMiddleware>();', 'app.UseMiddleware<JsonWebTokenMiddleware>();','app.MapControllers().WithMetadata(']:
        require(downstream in program and program.index(gate)<program.index(downstream),'Privacy policy must precede '+downstream)
    policy=(root/'Rigging/Hosting/SecurityResponseCacheMiddleware.cs').read_text()
    require('response.Headers.CacheControl = "no-store";' in policy and 'response.Headers.Pragma = "no-cache";' in policy and 'response.Headers.Expires = "Thu, 01 Jan 1970 00:00:00 GMT";' in policy,'Complete private response header policy')
    require('context.Response.OnStarting(static state =>' in policy and 'Apply((HttpResponse)state);' in policy,'Reassert final headers after downstream callbacks')
    require('Apply(context.Response);' in policy and 'if (!context.Response.HasStarted) Apply(context.Response);' in policy,'Cover early and unsent response paths')
    for path,call in [('Rigging/Authentication/SessionProtocol.cs','SecurityResponseCacheMiddleware.Apply(response)'),('Controllers/AccountSessionController.cs','SecurityResponseCacheMiddleware.Apply(Response)')]:
        require(call in (root/path).read_text(),'Direct credential response defense: '+path)
    fallback=(root/'Rigging/Hosting/HttpExceptionFallbackMiddleware.cs').read_text()
    require('when (context.RequestAborted.IsCancellationRequested) { throw; }' in fallback,'Do not fabricate cancellation responses')
    require('when (!context.Response.HasStarted)' in fallback and 'context.Response.Clear();' in fallback and 'SecurityResponseCacheMiddleware.Apply(context.Response);' in fallback,'Clear unsent error responses and reapply privacy')
    require('request.StatusCode' in fallback and 'StatusCodes.Status500InternalServerError' in fallback,'Preserve known HTTP status and unexpected 500')
    require('logger.LogError("HTTP request failed before response start. Exception type {ExceptionType}.", error.GetType().Name);' in fallback,'Sanitized logging without exception/body/credentials')
    require('Shared_cache_does_not_reuse_two_accounts_or_anonymous_bodies_or_credential_headers' in (root/'treehammock.Tests/Integration/KestrelCacheTests.cs').read_text(),'Native cache acceptance must remain authored')
    return dict(status='SourceContractsConsistent',qualification='NotRun',public_production_opt_ins=0,native_required=['fast','sql-harness','sql','system'])

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,default=ROOT);args=parser.parse_args()
    try: print(json.dumps(validate(args.root),indent=2));return 0
    except (ValueError, OSError, KeyError) as error: print(str(error));return 1

if __name__=='__main__':raise SystemExit(main())
