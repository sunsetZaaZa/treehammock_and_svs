using System.Diagnostics;
using System.Text.Json;
using Treehammock.SessionValidation.Core;
using Xunit;
namespace Treehammock.SessionValidation.CacheTests;

public sealed class CacheCostTests
{
    [Fact] public async Task Local_hit_and_miss_cost_sample_records_actual_call_counts_without_secrets()
    {
        var samples=new List<object>();
        foreach(bool hit in new[]{true,false})
        {
            using var h=new CacheHarness();if(!hit)h.Cache.Index=null;
            for(int n=0;n<10;n++)Assert.Equal(SessionDecision.Active,(await h.Validate(token:TestContext.Current.CancellationToken)).Decision);
            h.Cache.Keys.Clear();h.Refill.Requests.Clear();h.Db.Calls=0;
            long allocation=GC.GetTotalAllocatedBytes(true);var timings=new List<double>();
            for(int n=0;n<100;n++)
            {var timer=Stopwatch.StartNew();Assert.Equal(SessionDecision.Active,(await h.Validate(token:TestContext.Current.CancellationToken)).Decision);timings.Add(timer.Elapsed.TotalMilliseconds);}
            timings.Sort();Assert.Equal(hit?200:100,h.Cache.Keys.Count);Assert.Equal(hit?0:100,h.Db.Calls);Assert.Equal(hit?0:100,h.Refill.Requests.Count);
            samples.Add(new{scenario=hit?"coherent-hit":"index-miss",requests=100,cache_gets=h.Cache.Keys.Count,ysql_reads=h.Db.Calls,refill_attempts=h.Refill.Requests.Count,p50_ms=timings[49],p95_ms=timings[94],p99_ms=timings[98],process_allocation_bytes=GC.GetTotalAllocatedBytes(true)-allocation});
        }
        string? directory=Environment.GetEnvironmentVariable("SVS06_EVIDENCE_DIRECTORY");
        if(directory is not null)
        {Directory.CreateDirectory(directory);await File.WriteAllTextAsync(Path.Combine(directory,$"cache-cost-net{Environment.Version.Major}.json"),JsonSerializer.Serialize(new{scope="Local real-JWT with storage doubles; allocation is process-wide and may include runner work; no native latency/SLO proof",samples},new JsonSerializerOptions{WriteIndented=true}),TestContext.Current.CancellationToken);}
    }
}
