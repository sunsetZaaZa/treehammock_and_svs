using System.Diagnostics;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using treehammock.Rigging.Config;
using treehammock.Rigging.Hosting;
using treehammock.Tests.Infrastructure;

namespace treehammock.Tests.Integration;

public sealed class Cor23FBodyResourceTests
{
    [Fact]
    public async Task Kestrel_capacity_rejects_without_queueing_then_records_bounded_expansion_resource_sample()
    {
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);deadline.CancelAfter(TimeSpan.FromSeconds(30));
        await using var host=await Cor23FBodyFixture.StartAsync(true,new(){ConcurrentRequests=2});
        var hold=host.App.Services.GetRequiredService<Cor23FHold>();
        using var one=Cor23FBodyFixture.Request(new byte[]{123,125},route:"/fixture/hold");
        using var two=Cor23FBodyFixture.Request(new byte[]{123,125},route:"/fixture/hold");
        var first=host.Client.SendAsync(one,deadline.Token);var second=host.Client.SendAsync(two,deadline.Token);
        try
        {
            await hold.Full.Task.WaitAsync(deadline.Token);
            using var rejected=Cor23FBodyFixture.Request(new byte[]{123,125});
            using var response=await host.Client.SendAsync(rejected,deadline.Token);
            await Cor23FBodyFixture.AssertError(response,503,RequestBodyMiddleware.CapacityExceeded);
            Assert.Equal(TimeSpan.FromSeconds(2),response.Headers.RetryAfter!.Delta);
        }
        finally { hold.Release.TrySetResult(true); }
        using var heldOne=await first;using var heldTwo=await second;Assert.Equal(204,(int)heldOne.StatusCode);Assert.Equal(204,(int)heldTwo.StatusCode);
        byte[] compressed=Cor23FBodyFixture.Encode(Cor23FBodyFixture.JsonBytes(RequestBodySettings.DefaultDecodedBytes),"br");
        using var process=Process.GetCurrentProcess();long allocation=GC.GetTotalAllocatedBytes();long memory=process.WorkingSet64;var cpu=process.TotalProcessorTime;
        var samples=new List<double>();var wall=Stopwatch.StartNew();
        // Two workers hold at most the declared capacity, each sends six maximum expanded bodies.
        var workers=Enumerable.Range(0,2).Select(async _=>
        {
            var times=new List<double>();
            for(int index=0;index<6;index++)
            {
                using var request=Cor23FBodyFixture.Request(compressed,"br",chunked:true);
                var timer=Stopwatch.StartNew();using var response=await host.Client.SendAsync(request,deadline.Token);
                Assert.Equal(200,(int)response.StatusCode);await response.Content.ReadAsByteArrayAsync(deadline.Token);times.Add(timer.Elapsed.TotalMilliseconds);
            }
            return times;
        }).ToArray();
        foreach(var times in await Task.WhenAll(workers)) samples.AddRange(times);
        samples.Sort();process.Refresh();
        var report=new {kind="COR23F local resource sample",samples=samples.Count,concurrency=2,encodedBytes=compressed.Length,decodedBytes=RequestBodySettings.DefaultDecodedBytes,
            wallMilliseconds=wall.Elapsed.TotalMilliseconds,cpuMilliseconds=(process.TotalProcessorTime-cpu).TotalMilliseconds,
            allocatedBytes=GC.GetTotalAllocatedBytes()-allocation,workingSetDelta=process.WorkingSet64-memory,peakWorkingSetBytes=process.PeakWorkingSet64,
            p95Milliseconds=samples[(int)Math.Ceiling(samples.Count*.95)-1],p99Milliseconds=samples[(int)Math.Ceiling(samples.Count*.99)-1],
            configuredBodyBufferDiskSpillBytes=0,bodyBufferKind="fixed managed arrays + read-only MemoryStream",qualification="Local sample only; COR22 capacity qualification required"};
        TestContext.Current.SendDiagnosticMessage(JsonSerializer.Serialize(report));Assert.Equal(12,host.Visits.Accepted);
    }
    [Fact]
    public async Task Kestrel_slow_body_gets_exact_timeout_and_disconnect_never_executes_endpoint_or_leaks_capacity()
    {
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);deadline.CancelAfter(TimeSpan.FromSeconds(10));
        await using var host=await Cor23FBodyFixture.StartAsync(true,new(){ConcurrentRequests=1,ReadMilliseconds=100});
        var address=host.Client.BaseAddress!;
        using(var slow=new System.Net.Sockets.TcpClient())
        {
            await slow.ConnectAsync(address.Host,address.Port,deadline.Token);
            var stream=slow.GetStream();
            byte[] partial=System.Text.Encoding.ASCII.GetBytes("POST /fixture/body HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{}");
            await stream.WriteAsync(partial,deadline.Token);
            using var reader=new StreamReader(stream);
            string response=await reader.ReadToEndAsync(deadline.Token);
            Assert.Contains("408",response);Assert.Contains(RequestBodyMiddleware.BodyTimeout,response);Assert.Contains("no-store",response);
        }
        using(var disconnected=new System.Net.Sockets.TcpClient())
        {
            await disconnected.ConnectAsync(address.Host,address.Port,deadline.Token);
            await disconnected.GetStream().WriteAsync(System.Text.Encoding.ASCII.GetBytes("POST /fixture/body HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\nx"),deadline.Token);
        }
        Assert.Equal(0,host.Visits.Accepted);
        // Disconnect cleanup is asynchronous; only bounded 503 retry is permitted until the lease returns.
        for(int attempt=0;attempt<20;attempt++)
        {
            using var request=Cor23FBodyFixture.Request(new byte[]{123,125});using var response=await host.Client.SendAsync(request,deadline.Token);
            if((int)response.StatusCode==200) { Assert.Equal(1,host.Visits.Accepted);return; }
            await Cor23FBodyFixture.AssertError(response,503,RequestBodyMiddleware.CapacityExceeded);
            await Task.Delay(20,deadline.Token);
        }
        Assert.Fail("Disconnect did not release body capacity within the bounded deadline.");
    }

}
