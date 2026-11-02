using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Treehammock.SessionValidation.Client;
using Treehammock.SessionValidation.Contracts;
using Svs.Benchmark;

if (args is not ["--stdin"]) { Console.WriteLine("{\"status\":\"Refused\",\"code\":\"PRIVATE_STDIN_REQUIRED\"}");return 1; }
byte[] raw=new byte[262145];int length=0;
try
{
    using var input=Console.OpenStandardInput();
    while(length<raw.Length){int n=await input.ReadAsync(raw.AsMemory(length));if(n==0)break;length+=n;}
    if(length==raw.Length)throw new InvalidOperationException();
    using var doc=JsonDocument.Parse(raw.AsMemory(0,length),new JsonDocumentOptions{MaxDepth=8});BenchHarness.Unique(doc.RootElement);
    var options=JsonSerializer.Deserialize<BenchInput>(raw.AsSpan(0,length),BenchHarness.Json)??throw new InvalidOperationException();
    using var stop=new CancellationTokenSource();Console.CancelKeyPress+=(_,e)=>{e.Cancel=true;stop.Cancel();};
    var result=await BenchHarness.RunAsync(options,stop.Token);Console.WriteLine(JsonSerializer.Serialize(result,BenchHarness.Json));return result.Status=="Completed"?0:2;
}
catch { Console.WriteLine("{\"status\":\"Refused\",\"code\":\"BENCHMARK_INPUT_OR_TRANSPORT_REFUSED\"}");return 1; }
finally { CryptographicOperations.ZeroMemory(raw); }

namespace Svs.Benchmark
{
public sealed record BenchClient(string Replica,ClientOptions Options);
public sealed record BenchVector(string Label,string Credential,string Action,string ExpectedDecision,Guid Account,Guid Family,long Generation,uint Protocol);
public sealed record BenchInput(BenchClient[] Clients,BenchVector[] Vectors,int DurationSeconds,int Concurrency,int RequestsPerSecond,long RequestLimit);
public sealed record BenchResult(string Status,string Scope,long Requests,long UnexpectedDecisions,long FalseActive,long TupleMismatches,long LatencyOverflow,double Seconds,double RequestsPerSecond,double RequestsPerSecondPerDriverCore,long P50Us,long P95Us,long P99Us,double DriverCpuSeconds,long DriverPeakWorkingSetBytes,int DriverPeakFileDescriptors,Dictionary<string,long> Decisions,Dictionary<string,long> ReplicaSamples,bool NativeQualified=false,bool GrantRights=false,bool ReleaseReady=false);
public static class BenchHarness
{
    public static readonly JsonSerializerOptions Json=new(){PropertyNamingPolicy=JsonNamingPolicy.CamelCase,UnmappedMemberHandling=JsonUnmappedMemberHandling.Disallow,MaxDepth=8};
    private static readonly HashSet<string> Labels=["active","malformed","wrong-signature","revoked","forbidden","expired","refresh-race","logout-race"];
    public static void Unique(JsonElement e){if(e.ValueKind==JsonValueKind.Object){var names=new HashSet<string>(StringComparer.Ordinal);foreach(var p in e.EnumerateObject()){if(!names.Add(p.Name))throw new InvalidOperationException();Unique(p.Value);}}else if(e.ValueKind==JsonValueKind.Array)foreach(var item in e.EnumerateArray())Unique(item);}
    public static async Task<BenchResult> RunAsync(BenchInput input,CancellationToken cancellationToken=default)
    {
        if(input.DurationSeconds is <1 or >90000 || input.Concurrency is <1 or >64 || input.RequestsPerSecond is <1 or >100000 || input.RequestLimit is <1 or >100000000 || input.Clients is not {Length:>=1 and <=9} || input.Vectors is not {Length:>=1 and <=8})throw new ArgumentException("Bounded benchmark required.");
        if(input.Clients.Any(c=>c is null||c.Replica is null||!System.Text.RegularExpressions.Regex.IsMatch(c.Replica,"^svs-([1-8]|vip)$")||string.IsNullOrEmpty(c.Options.PrivateAddress))||input.Clients.Select(c=>c.Replica).Distinct().Count()!=input.Clients.Length)throw new ArgumentException("Explicit private replicas required.");
        foreach(var v in input.Vectors)
        {
            if(v is null||!Labels.Contains(v.Label)||!CallerPolicy.IsSupportedAction(v.Action)||v.ExpectedDecision is not ("Active" or "Unauthenticated" or "Forbidden" or "Unavailable")||v.Credential is null||v.Credential.Length is <1 or >8192||v.Credential.Any(c=>c<=0x20||c>=0x7f))throw new ArgumentException("Reviewed vectors required.");
            if(v.ExpectedDecision=="Active"&&(v.Account==Guid.Empty||v.Family==Guid.Empty||v.Generation<1||v.Protocol!=2))throw new ArgumentException("Verified tuple oracle required.");
        }
        if(input.Vectors.Select(v=>v.Label).Distinct().Count()!=input.Vectors.Length)throw new ArgumentException("Unique vectors required.");
        // Bounded SDKs, N worker tasks and one fixed histogram: no per-call queue,
        // retained samples or positive authorization cache, including a 24h run.
        var clients=new List<SessionValidatorClient>();
        try
        {
            foreach(var c in input.Clients)clients.Add(new SessionValidatorClient(c.Options));
            long[] histogram=new long[65537];long[] decisions=new long[4];long[] coverage=new long[clients.Count];long requests=0,next=0,unexpected=0,falseActive=0,tupleMismatch=0,overflow=0;
            using var stop=CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            long started=Stopwatch.GetTimestamp();stop.CancelAfter(TimeSpan.FromSeconds(input.DurationSeconds));using var process=Process.GetCurrentProcess();double cpuStart=process.TotalProcessorTime.TotalSeconds;long peakMemory=process.WorkingSet64;int peakFd=FdCount();
            async Task Sample()
            {
                try{while(!stop.IsCancellationRequested){process.Refresh();Interlocked.Exchange(ref peakMemory,Math.Max(Interlocked.Read(ref peakMemory),process.WorkingSet64));Interlocked.Exchange(ref peakFd,Math.Max(Volatile.Read(ref peakFd),FdCount()));await Task.Delay(250,stop.Token);}}
                catch(OperationCanceledException)when(stop.IsCancellationRequested){}
            }
            async Task Worker()
            {
                try
                {
                    while(!stop.IsCancellationRequested)
                    {
                        long number=Interlocked.Increment(ref next)-1;if(number>=input.RequestLimit)return;
                        double wait=number/(double)input.RequestsPerSecond-Stopwatch.GetElapsedTime(started).TotalSeconds;
                        if(wait>0)await Task.Delay(TimeSpan.FromSeconds(wait),stop.Token);
                        if(stop.IsCancellationRequested)return;
                        int replica=(int)(number%clients.Count);var vector=input.Vectors[(number/clients.Count)%input.Vectors.Length];long stamp=Stopwatch.GetTimestamp();
                        var result=await clients[replica].ValidateAsync(vector.Credential,vector.Action,DateTimeOffset.UtcNow.AddMilliseconds(input.Clients[replica].Options.RequestTimeoutMilliseconds),stop.Token);
                        if(stop.IsCancellationRequested && result.Decision==ValidationDecision.Unavailable)return;
                        long elapsed=(long)Math.Ceiling(Stopwatch.GetElapsedTime(stamp).TotalMicroseconds);int bucket=(int)Math.Min(65536,elapsed/64);Interlocked.Increment(ref histogram[bucket]);if(bucket==65536)Interlocked.Increment(ref overflow);
                        Interlocked.Increment(ref requests);Interlocked.Increment(ref coverage[replica]);Interlocked.Increment(ref decisions[(int)result.Decision]);
                        if(result.Decision.ToString()!=vector.ExpectedDecision)Interlocked.Increment(ref unexpected);
                        if(result.Decision==ValidationDecision.Active)
                        {
                            bool tuple=result.Subject is {} s&&s.AccountId==vector.Account&&s.SessionFamilyId==vector.Family&&s.Generation==vector.Generation&&s.ProtocolVersion==vector.Protocol;
                            if(!tuple)Interlocked.Increment(ref tupleMismatch);
                            if(vector.ExpectedDecision!="Active"||!tuple)Interlocked.Increment(ref falseActive);
                        }
                    }
                }
                catch(OperationCanceledException)when(stop.IsCancellationRequested){}
            }
            var sampler=Sample();await Task.WhenAll(Enumerable.Range(0,input.Concurrency).Select(_=>Worker()));await stop.CancelAsync();await sampler;
            double seconds=Stopwatch.GetElapsedTime(started).TotalSeconds;process.Refresh();long Quantile(double p){if(requests==0)return 0;long target=(long)Math.Ceiling(requests*p),sum=0;for(int i=0;i<histogram.Length;i++){sum+=histogram[i];if(sum>=target)return (i+1)*64L;}throw new InvalidOperationException();}
            var codes=Enum.GetNames<ValidationDecision>();return new(cancellationToken.IsCancellationRequested?"Cancelled":"Completed","Private real SDK driver; native measurements require independent observer proofs",requests,unexpected,falseActive,tupleMismatch,overflow,seconds,requests/seconds,requests/seconds/Environment.ProcessorCount,Quantile(.5),Quantile(.95),Quantile(.99),process.TotalProcessorTime.TotalSeconds-cpuStart,peakMemory,peakFd,codes.Select((code,i)=>(code,i)).ToDictionary(x=>x.code,x=>decisions[x.i]),input.Clients.Select((c,i)=>(c.Replica,i)).ToDictionary(x=>x.Replica,x=>coverage[x.i]));
        }
        finally {foreach(var client in clients)await client.DisposeAsync();}
    }
    private static int FdCount()=>OperatingSystem.IsLinux()?Directory.GetFiles("/proc/self/fd").Length:0;
}
}
