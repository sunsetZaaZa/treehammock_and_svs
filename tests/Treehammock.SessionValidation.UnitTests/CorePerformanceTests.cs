using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using NodaTime;
using Treehammock.SessionValidation.Core;
using Xunit;
using Legacy = Svs02.FrozenBaseline;

namespace Treehammock.SessionValidation.UnitTests;

[CollectionDefinition("IsolatedCorePerformance", DisableParallelization = true)]
public sealed class IsolatedCorePerformanceCollection;

[Collection("IsolatedCorePerformance")]
public sealed class CorePerformanceTests
{
    [Fact]
    public async Task Record_original_and_extracted_verifier_CPU_and_allocations()
    {
        var legacy = new Legacy.JsonWebTokenUtility(new Legacy.RecordingLogger<Legacy.JsonWebTokenUtility>(), new Legacy.Options<Legacy.JWTSettings>(new()));
        var core = new TreehammockTokenVerifier(); var key = TestSessions.Key(); string token = TestSessions.Mint();
        var now = TestSessions.Now; var expiry = now + Duration.FromMinutes(5);
        async Task Old() { var r=await legacy.ValidateAccessToken(token,key,now,expiry); Assert.Equal(Legacy.IntraMessage.TOKEN_PASSED_VALIDATION,r.Item1); }
        async Task New() { var r=await core.ValidateAsync(token,key,TestSessions.Issuer,now,expiry); Assert.Equal(TokenStatus.Passed,r.Status); }
        for(int i=0;i<1000;i++) { await Old(); await New(); }
        const int iterations=5000;
        async Task<Measurement> Measure(Func<Task> operation)
        {
            long allocated=GC.GetTotalAllocatedBytes(true); long start=Stopwatch.GetTimestamp();
            for(int i=0;i<iterations;i++)await operation();
            long end=Stopwatch.GetTimestamp(); long bytes=GC.GetTotalAllocatedBytes(true)-allocated;
            return new((end-start)*1_000_000_000.0/Stopwatch.Frequency/iterations,bytes/(double)iterations);
        }
        var oldResults=new List<Measurement>(); var newResults=new List<Measurement>();
        for(int round=0;round<5;round++)
        {
            if(round%2==0){oldResults.Add(await Measure(Old));newResults.Add(await Measure(New));}
            else{newResults.Add(await Measure(New));oldResults.Add(await Measure(Old));}
        }
        double oldBytes=oldResults.Select(x=>x.BytesPerCall).Order().ElementAt(2);
        double newBytes=newResults.Select(x=>x.BytesPerCall).Order().ElementAt(2);
        // Allocation ceiling is a local refactor regression check, not a throughput SLO.
        Assert.True(newBytes<=oldBytes*1.25+256,"Extracted verifier exceeded the local allocation regression allowance.");
        string? evidence=Environment.GetEnvironmentVariable("SVS02_EVIDENCE_DIRECTORY");
        if(!string.IsNullOrWhiteSpace(evidence))
        {
            Directory.CreateDirectory(evidence);
            string target=Environment.Version.Major==8?"net8.0":"net10.0";
            await File.WriteAllTextAsync(Path.Combine(evidence,"performance-"+target+".json"),JsonSerializer.Serialize(new
            {
                runtime=RuntimeInformation.FrameworkDescription,architecture=RuntimeInformation.ProcessArchitecture.ToString(),
                iterations_per_round=iterations,rounds=5,warmup_pairs=1000,
                original=oldResults,extracted=newResults,
                median_allocation_ratio=newBytes/oldBytes,
                median_latency_ratio=newResults.Select(x=>x.NanosecondsPerCall).Order().ElementAt(2)/oldResults.Select(x=>x.NanosecondsPerCall).Order().ElementAt(2),
                scope="Local sequential synthetic verifier sample; no end-to-end SLO, physical-host capacity or production claim"
            },new JsonSerializerOptions{WriteIndented=true}),TestContext.Current.CancellationToken);
        }
    }
    private sealed record Measurement(double NanosecondsPerCall,double BytesPerCall);
}
