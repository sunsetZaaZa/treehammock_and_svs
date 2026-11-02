using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
using Svs.Benchmark;
using Treehammock.SessionValidation.Api;
using Treehammock.SessionValidation.Client;
using Treehammock.SessionValidation.HostTests;
using Treehammock.SessionValidation.Storage;
using Xunit;
namespace Svs.Qualification.Tests;
public sealed class BenchmarkTests(HostFixture fixture):IClassFixture<HostFixture>
{
    private HostSettings Settings()=>fixture.Settings(j=>j["actionPolicy"]=JsonNode.Parse("""{"version":"bench.v1","requirements":{"backup.read":"account.read","backup.write":"account.manage"}}"""));
    private ClientOptions Options(HostSettings s)
    {
        var p=Path.Combine(fixture.Directory,Guid.NewGuid()+".pfx");File.WriteAllBytes(p,fixture.Client.Export(X509ContentType.Pfx,"bench-fixture"));return new(){TlsName="localhost",PrivateAddress="127.0.0.1",Port=s.Port,ServerRootCertificatePath=s.ServerRootCertificatePath,ServerLeafSha256=[HostFixture.Pin(fixture.Server)],ClientCertificatePath=p,ClientCertificatePassword="bench-fixture",ClientRootCertificatePath=s.ClientRootCertificatePath,ServiceIdentity=HostFixture.Identity,PolicyVersion=s.ActionPolicy.Version};
    }
    private static BenchVector Vector(RpcResources r,string label,string expected="Active",bool wrongTuple=false)=>new(label,r.Credential(label=="wrong-signature"),label=="forbidden"?"backup.write":"backup.read",expected,wrongTuple?Guid.NewGuid():r.Identity.AccountId,r.Identity.FamilyId,r.Identity.Generation,(uint)r.Identity.ProtocolVersion);
    [Fact] public async Task Real_sdk_workers_use_two_private_mtls_hosts_without_positive_cache_or_sensitive_output()
    {
        var r=new RpcResources();var s=Settings();var t=Settings();await using var a=QualificationHostFactory.Build(s,r);await using var b=QualificationHostFactory.Build(t,r);await a.StartAsync(TestContext.Current.CancellationToken);await b.StartAsync(TestContext.Current.CancellationToken);
        var input=new BenchInput([new("svs-1",Options(s)),new("svs-2",Options(t))],[Vector(r,"active"),Vector(r,"wrong-signature","Unauthenticated"),Vector(r,"forbidden","Forbidden")],10,8,3000,2048);
        var result=await BenchHarness.RunAsync(input,TestContext.Current.CancellationToken);Assert.Equal("Completed",result.Status);Assert.Equal(2048,result.Requests);Assert.Equal(2048,r.Calls);Assert.Equal(0,result.FalseActive);Assert.Equal(0,result.UnexpectedDecisions);Assert.Equal(1024,result.ReplicaSamples["svs-1"]);Assert.Equal(1024,result.ReplicaSamples["svs-2"]);Console.WriteLine("SVS22_LOCAL_BENCHMARK="+JsonSerializer.Serialize(result,BenchHarness.Json));Assert.False(result.NativeQualified);Assert.True(result.P99Us>0);Assert.True(result.DriverPeakWorkingSetBytes>0);string json=JsonSerializer.Serialize(result);Assert.DoesNotContain(r.Credential(),json);Assert.DoesNotContain(r.Identity.AccountId.ToString(),json);
    }
    [Fact] public async Task Actual_cli_reads_private_stdin_uses_sdk_and_exports_only_metrics()
    {
        var r=new RpcResources();var s=Settings();await using var host=QualificationHostFactory.Build(s,r);await host.StartAsync(TestContext.Current.CancellationToken);
        var input=new BenchInput([new("svs-1",Options(s))],[Vector(r,"active")],5,2,100,8);
        var dotnet=Path.Combine(Environment.GetEnvironmentVariable("DOTNET_ROOT")??throw new InvalidOperationException(),"dotnet");
        var start=new System.Diagnostics.ProcessStartInfo(dotnet){UseShellExecute=false,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true};var configuration=new DirectoryInfo(AppContext.BaseDirectory).Parent!.Name;var executable=Path.GetFullPath(Path.Combine(AppContext.BaseDirectory,"../../../..","Treehammock.SessionValidation.QualificationBenchmark","bin",configuration,"net10.0","Svs.Benchmark.dll"));start.ArgumentList.Add(executable);start.ArgumentList.Add("--stdin");
        using var process=System.Diagnostics.Process.Start(start)??throw new InvalidOperationException();await process.StandardInput.WriteAsync(JsonSerializer.Serialize(input,BenchHarness.Json));process.StandardInput.Close();var output=await process.StandardOutput.ReadToEndAsync(TestContext.Current.CancellationToken);var error=await process.StandardError.ReadToEndAsync(TestContext.Current.CancellationToken);await process.WaitForExitAsync(TestContext.Current.CancellationToken);Assert.True(process.ExitCode==0,"CLI refused: "+output);Assert.Empty(error);Assert.DoesNotContain(r.Credential(),output);Assert.DoesNotContain(r.Identity.AccountId.ToString(),output);var result=JsonSerializer.Deserialize<BenchResult>(output,BenchHarness.Json)!;Assert.Equal(8,result.Requests);Assert.Equal(8,r.Calls);Assert.False(result.NativeQualified);Assert.Equal(0,result.UnexpectedDecisions);
    }
    [Theory][InlineData(false)][InlineData(true)] public async Task False_active_and_identity_oracle_drift_are_measured(bool wrongTuple)
    {
        var r=new RpcResources();var s=Settings();await using var host=QualificationHostFactory.Build(s,r);await host.StartAsync(TestContext.Current.CancellationToken);var result=await BenchHarness.RunAsync(new([new("svs-1",Options(s))],[Vector(r,"active",wrongTuple?"Active":"Unauthenticated",wrongTuple)],5,2,100,4),TestContext.Current.CancellationToken);Assert.Equal(4,result.FalseActive);Assert.Equal(wrongTuple?4:0,result.TupleMismatches);Assert.False(result.NativeQualified);
    }
    [Fact] public async Task Authority_outage_is_closed_and_cancellation_has_bounded_cleanup()
    {
        var r=new RpcResources{Status=AuthorityReadStatus.Unavailable};var s=Settings();await using var host=QualificationHostFactory.Build(s,r);await host.StartAsync(TestContext.Current.CancellationToken);var v=Vector(r,"active","Unavailable");using var stop=new CancellationTokenSource(200);var result=await BenchHarness.RunAsync(new([new("svs-1",Options(s))],[v],5,2,100,1000),stop.Token);Assert.Equal("Cancelled",result.Status);Assert.Equal(0,result.FalseActive);Assert.Equal(0,result.UnexpectedDecisions);Assert.True(result.Seconds<3);Assert.False(result.ReleaseReady);
    }
    [Theory][InlineData(0,1)][InlineData(65,1)][InlineData(1,0)][InlineData(1,90001)]public async Task Bounds_are_refused_before_network(int concurrency,int duration)
    {
        await Assert.ThrowsAsync<ArgumentException>(()=>BenchHarness.RunAsync(new([],[],duration,concurrency,10,10),TestContext.Current.CancellationToken));
    }
    [Fact]public void Duplicate_or_unknown_config_properties_are_refused()
    {
        using var doc=JsonDocument.Parse("{\"clients\":[],\"clients\":[]}");Assert.Throws<InvalidOperationException>(()=>BenchHarness.Unique(doc.RootElement));Assert.Throws<JsonException>(()=>JsonSerializer.Deserialize<BenchInput>("{\"unknown\":true}",BenchHarness.Json));
    }
}
