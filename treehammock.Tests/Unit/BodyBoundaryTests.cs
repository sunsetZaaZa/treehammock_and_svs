using System.ComponentModel.DataAnnotations;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using treehammock.Rigging.Config;
using treehammock.DataLayer.Operations;
using treehammock.Rigging.Hosting;
using treehammock.Rigging.Operations;
using treehammock.Tests.Infrastructure;

namespace treehammock.Tests.Unit;

public sealed class Cor23FBodyBoundaryTests
{
    private static DefaultHttpContext Context(Stream body)
    {
        var http=new DefaultHttpContext();http.Request.Method="POST";http.Request.Body=body;
        http.Response.Body=new MemoryStream();return http;
    }
    private static async Task<string> Body(DefaultHttpContext http)
    { http.Response.Body.Position=0;return await new StreamReader(http.Response.Body,leaveOpen:true).ReadToEndAsync(); }
    private sealed class WaitingStream : Stream
    {
        public override bool CanRead=>true;public override bool CanWrite=>false;public override bool CanSeek=>false;
        public override long Length=>throw new NotSupportedException();public override long Position {get=>throw new NotSupportedException();set=>throw new NotSupportedException();}
        public override int Read(byte[] buffer,int offset,int count)=>throw new InvalidOperationException("Async only.");
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer,CancellationToken token=default)
        { await Task.Delay(Timeout.Infinite,token);return 0; }
        public override void Flush(){}public override long Seek(long offset,SeekOrigin origin)=>throw new NotSupportedException();
        public override void SetLength(long value)=>throw new NotSupportedException();public override void Write(byte[] buffer,int offset,int count)=>throw new NotSupportedException();
    }
    [Fact]
    public async Task Read_deadline_returns_408_and_caller_cancellation_propagates_without_envelope_and_releases_capacity()
    {
        using var policy=new RequestBodyPolicy(Options.Create(new RequestBodySettings {ReadMilliseconds=100,ConcurrentRequests=1,EncodedBytes=64,DecodedBytes=64}));
        int visits=0;var middleware=new RequestBodyMiddleware(_=>{Interlocked.Increment(ref visits);return Task.CompletedTask;},policy);
        var slow=Context(new WaitingStream());await middleware.InvokeAsync(slow);
        Assert.Equal(408,slow.Response.StatusCode);Assert.Contains(RequestBodyMiddleware.BodyTimeout,await Body(slow));
        Assert.Equal("no-store",slow.Response.Headers.CacheControl.ToString());Assert.Equal(0,visits);
        using var cancel=new CancellationTokenSource();var caller=Context(new WaitingStream());caller.RequestAborted=cancel.Token;
        var pending=middleware.InvokeAsync(caller);cancel.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>pending);Assert.Equal(0,caller.Response.Body.Length);
        var good=Context(new MemoryStream(Encoding.UTF8.GetBytes("{}")));await middleware.InvokeAsync(good);Assert.Equal(1,visits);
        using var domainCancel=new CancellationTokenSource();var domain=Context(new MemoryStream());domain.RequestAborted=domainCancel.Token;
        var operations=new SecurityOperationMiddleware(_=>{domainCancel.Cancel();throw new SecurityOperationException("FIXTURE_DENIAL",409);});
        await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>operations.InvokeAsync(domain,null!));Assert.Equal(0,domain.Response.Body.Length);
    }
    [Fact]
    public async Task Capacity_is_held_through_downstream_and_released_on_errors_with_original_request_restored()
    {
        using var policy=new RequestBodyPolicy(Options.Create(new RequestBodySettings {ConcurrentRequests=1,EncodedBytes=64,DecodedBytes=128}));
        var arrived=new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var release=new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        int visits=0;var middleware=new RequestBodyMiddleware(async _=>{Interlocked.Increment(ref visits);arrived.TrySetResult(true);await release.Task;},policy);
        var first=Context(new MemoryStream(Cor23FBodyFixture.Encode(Encoding.UTF8.GetBytes("{}"),"gzip")));
        var original=first.Request.Body;first.Request.Headers.ContentEncoding="gzip";first.Request.ContentLength=original.Length;
        var pending=middleware.InvokeAsync(first);
        await ObserveHeldRequest(pending, release, async () => {
            await arrived.Task.WaitAsync(TimeSpan.FromSeconds(2));
            var second=Context(new MemoryStream(Encoding.UTF8.GetBytes("{}")));await middleware.InvokeAsync(second);
            Assert.Equal(503,second.Response.StatusCode);Assert.Contains(RequestBodyMiddleware.CapacityExceeded,await Body(second));Assert.Equal("2",second.Response.Headers.RetryAfter.ToString());
        });
        Assert.Same(original,first.Request.Body);Assert.Equal("gzip",first.Request.Headers.ContentEncoding.ToString());Assert.Equal(original.Length,first.Request.ContentLength);
        var failing=new RequestBodyMiddleware(_=>throw new IOException("private-proof"),policy);
        var failed=Context(new MemoryStream(Encoding.UTF8.GetBytes("{}")));await Assert.ThrowsAsync<IOException>(()=>failing.InvokeAsync(failed));
        await middleware.InvokeAsync(Context(new MemoryStream(Encoding.UTF8.GetBytes("{}"))));Assert.Equal(2,visits);
    }
    private static async Task ObserveHeldRequest(Task pending, TaskCompletionSource<bool> release, Func<Task> assertions)
    {
        Exception? primary = null, cleanup = null;
        try { await assertions(); }
        catch (Exception error) { primary = error; }
        finally
        {
            release.TrySetResult(true);
            try { await pending.WaitAsync(TimeSpan.FromSeconds(5)); }
            catch (Exception error) {
                _ = pending.ContinueWith(task => { _ = task.Exception; }, CancellationToken.None,
                    TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
                cleanup = error;
            }
        }
        if (primary is not null && cleanup is not null) throw new AggregateException(primary, cleanup);
        if (primary is not null) System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(primary).Throw();
        if (cleanup is not null) System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(cleanup).Throw();
    }

    [Theory]
    [InlineData(false, false)] [InlineData(true, false)] [InlineData(false, true)]
    public async Task Assertion_or_timeout_cleanup_observes_pending_body_work_and_restores_capacity(bool timeout, bool failCleanup)
    {
        using var policy = new RequestBodyPolicy(Options.Create(new RequestBodySettings {ConcurrentRequests=1,EncodedBytes=64,DecodedBytes=128}));
        var arrived = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var middleware = new RequestBodyMiddleware(async _ => {
            arrived.TrySetResult(true); await release.Task;
            if(failCleanup) throw new IOException("cleanup evidence");
        },policy);
        var http = Context(new MemoryStream(Cor23FBodyFixture.Encode(Encoding.UTF8.GetBytes("{}"),"gzip")));
        var original = http.Request.Body;http.Request.Headers.ContentEncoding="gzip";http.Request.ContentLength=original.Length;
        var pending = middleware.InvokeAsync(http);
        Exception? failure = await Record.ExceptionAsync(() => ObserveHeldRequest(pending,release,async () => {
            await arrived.Task.WaitAsync(TimeSpan.FromSeconds(2));
            if(timeout) await new TaskCompletionSource<bool>().Task.WaitAsync(TimeSpan.FromMilliseconds(20));
            throw new InvalidOperationException("primary evidence");
        }));
        Assert.True(pending.IsCompleted);
        Assert.Same(original,http.Request.Body);Assert.Equal("gzip",http.Request.Headers.ContentEncoding.ToString());Assert.Equal(original.Length,http.Request.ContentLength);
        if(failCleanup) {
            var both = Assert.IsType<AggregateException>(failure);
            Assert.Equal("primary evidence",both.InnerExceptions[0].Message);
            Assert.Equal("cleanup evidence",both.InnerExceptions[1].Message);
        }
        else if(timeout) Assert.IsType<TimeoutException>(failure);
        else Assert.Equal("primary evidence",Assert.IsType<InvalidOperationException>(failure).Message);
        int recovered = 0;
        var good = new RequestBodyMiddleware(_ => { recovered++; return Task.CompletedTask; },policy);
        await good.InvokeAsync(Context(new MemoryStream(Encoding.UTF8.GetBytes("{}"))));Assert.Equal(1,recovered);
    }

    [Theory]
    [InlineData("gzip")] [InlineData("deflate")] [InlineData("br")]
    public async Task Trailing_frames_and_checksums_are_validated_and_decoder_errors_stay_narrow(string encoding)
    {
        byte[] complete=Cor23FBodyFixture.Encode(Cor23FBodyFixture.JsonBytes(32),encoding);
        var output=new byte[129];
        Assert.Equal(32,await StrictRequestBodyDecoder.DecodeAsync(encoding,complete,complete.Length,output,default));
        byte[] trailing=complete.Concat(new byte[]{0x77}).ToArray();
        await Assert.ThrowsAsync<InvalidDataException>(()=>StrictRequestBodyDecoder.DecodeAsync(encoding,trailing,trailing.Length,output,default));
        if(encoding is "gzip" or "deflate")
        {
            byte[] changed=(byte[])complete.Clone();changed[^1]^=0xff;
            await Assert.ThrowsAsync<InvalidDataException>(()=>StrictRequestBodyDecoder.DecodeAsync(encoding,changed,changed.Length,output,default));
        }
        if(encoding=="gzip")
        {
            byte[] multiple=complete.Concat(complete).ToArray();
            await Assert.ThrowsAsync<InvalidDataException>(()=>StrictRequestBodyDecoder.DecodeAsync(encoding,multiple,multiple.Length,output,default));
        }
    }
    [Theory]
    [InlineData(0,128,1,100)] [InlineData(128,0,1,100)] [InlineData(128,128,0,100)] [InlineData(128,128,1,0)]
    public void Invalid_budgets_cannot_create_the_immutable_host_policy(int encoded,int decoded,int concurrent,int milliseconds)
    {
        Assert.Throws<ValidationException>(()=>new RequestBodyPolicy(Options.Create(new RequestBodySettings {EncodedBytes=encoded,DecodedBytes=decoded,ConcurrentRequests=concurrent,ReadMilliseconds=milliseconds})));
    }
    [Fact]
    public async Task Canonical_reader_does_not_disguise_unrelated_IO_as_a_size_error()
    {
        var context=Context(new FailureStream());
        await Assert.ThrowsAsync<IOException>(()=>SecurityOperationMiddleware.CanonicalBodyAsync(context));
    }
    private sealed class FailureStream : MemoryStream
    {
        public override ValueTask<int> ReadAsync(Memory<byte> bytes,CancellationToken token=default)=>ValueTask.FromException<int>(new IOException("storage-proof"));
    }
}
