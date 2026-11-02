using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Logging;
using treehammock.Rigging.Hosting;

namespace treehammock.Tests.Unit;

public sealed class Cor23EResponsePolicyTests
{
    private sealed class Logger : ILogger<HttpExceptionFallbackMiddleware>
    {
        public readonly List<string> Messages=new();
        public bool IsEnabled(LogLevel level)=>true;
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public void Log<TState>(LogLevel level,EventId id,TState state,Exception? error,Func<TState,Exception?,string> formatter)
        { Assert.Null(error);Messages.Add(formatter(state,error)); }
    }
    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task Cleared_response_errors_keep_no_store_and_never_log_or_return_exception_proof(bool badRequest)
    {
        var context=new DefaultHttpContext();context.Response.Body=new MemoryStream();
        var logger=new Logger();var error=badRequest ? (Exception)new BadHttpRequestException("private-proof-body",413) : new InvalidOperationException("private-proof-body");
        var fallback=new HttpExceptionFallbackMiddleware(http=> {http.Response.Headers["AccessToken"]="partial-credential";throw error;},logger);
        var policy=new SecurityResponseCacheMiddleware(fallback.InvokeAsync);await policy.InvokeAsync(context);
        Assert.Equal(badRequest?413:500,context.Response.StatusCode);Assert.Equal("no-store",context.Response.Headers.CacheControl.ToString());
        Assert.False(context.Response.Headers.ContainsKey("AccessToken"));
        context.Response.Body.Position=0;string body=await new StreamReader(context.Response.Body).ReadToEndAsync();
        Assert.Contains(badRequest?HttpExceptionFallbackMiddleware.RequestErrorCode:HttpExceptionFallbackMiddleware.UnexpectedErrorCode,body);
        Assert.DoesNotContain("private-proof-body",body);Assert.All(logger.Messages,message=>Assert.DoesNotContain("private-proof-body",message));
    }
    [Fact]
    public async Task Caller_cancellation_escapes_without_a_fabricated_success_or_error_envelope()
    {
        using var cancel=new CancellationTokenSource();cancel.Cancel();
        var context=new DefaultHttpContext();context.RequestAborted=cancel.Token;context.Response.Body=new MemoryStream();
        var fallback=new HttpExceptionFallbackMiddleware(_=>Task.FromCanceled(cancel.Token),new Logger());
        await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>new SecurityResponseCacheMiddleware(fallback.InvokeAsync).InvokeAsync(context));
        Assert.Equal(0L,context.Response.Body.Length);Assert.Equal("no-store",context.Response.Headers.CacheControl.ToString());
    }
    private sealed class StartedFeature : HttpResponseFeature { public override bool HasStarted=>true; }
    [Fact]
    public async Task Started_response_failure_propagates_for_server_abort_instead_of_rewriting_a_committed_body()
    {
        var context=new DefaultHttpContext();context.Features.Set<IHttpResponseFeature>(new StartedFeature());
        var fallback=new HttpExceptionFallbackMiddleware(_=>throw new InvalidOperationException("started"),new Logger());
        await Assert.ThrowsAsync<InvalidOperationException>(()=>fallback.InvokeAsync(context));
    }
}
