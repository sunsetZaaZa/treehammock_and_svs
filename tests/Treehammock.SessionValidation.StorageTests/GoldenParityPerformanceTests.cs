using System.Diagnostics;
using NodaTime;
using Svs12.Golden;
using Svs12.Harness;
using Treehammock.SessionValidation.Core;
using Xunit;
namespace Treehammock.SessionValidation.StorageTests;
public sealed class GoldenParityPerformanceTests
{
    [Fact] public async Task Report_local_coordinator_overhead_without_inventing_an_approved_host_SLO()
    {
        using var h=new ParityHarness("issued-no-exp",true);var evaluator=new TreehammockSessionPolicyEvaluator();var key=TreehammockParityFixtures.Key();var coordinator=h.Coordinator();
        async Task Direct()=>Assert.Equal(SessionDecision.Active,await evaluator.EvaluateAccessAsync(h.Inputs,h.Credential,key,TreehammockParityFixtures.Corpus.Issuer));
        async Task Coordinated()=>Assert.Equal(SessionDecision.Active,(await coordinator.ValidateAsync(h.Credential,h.Case.RequiredCapability,h.Now+Duration.FromSeconds(2),TestContext.Current.CancellationToken)).Decision);
        for(int i=0;i<20;i++){await Direct();await Coordinated();}
        async Task<object> Measure(Func<Task> action)
        {
            var samples=new double[300];long bytes=GC.GetTotalAllocatedBytes(true);
            for(int i=0;i<samples.Length;i++){long start=Stopwatch.GetTimestamp();await action();samples[i]=Stopwatch.GetElapsedTime(start).TotalMicroseconds;}
            bytes=GC.GetTotalAllocatedBytes(true)-bytes;Array.Sort(samples);return new{Iterations=samples.Length,MedianMicroseconds=samples[150],P95Microseconds=samples[284],AllocatedBytes=bytes};
        }
        var direct=await Measure(Direct);var coordinated=await Measure(Coordinated);Assert.Equal(0,h.Database.Calls);Assert.Equal(0,h.Refill.Calls);Assert.Equal(640,h.Store.Gets);
        TreehammockParityFixtures.Report("performance",new{DirectPolicy=direct,CacheCoordinator=coordinated,Scope="In-process synthetic cache, actual JWS verification, not physical-host/middleware/network SLO",ApprovedCap="Not provided; informational measurement",NativeCasesExecuted=0});
        System.Security.Cryptography.CryptographicOperations.ZeroMemory(key);
    }
}
