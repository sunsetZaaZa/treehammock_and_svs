using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Treehammock.SessionValidation.Api;
using treehammock.Rigging.Fleet;
using Xunit;
namespace Treehammock.SessionValidation.HostTests;
public sealed class FleetProtocolTests(HostFixture fixture):IClassFixture<HostFixture>
{
    [Theory][InlineData("v1")][InlineData("missing-version")][InlineData("duplicate")][InlineData("unknown")][InlineData("oversized")][InlineData("deep")][InlineData("number-enum")]
    public void Closed_v2_parser_rejects_ambiguous_or_legacy_frames(string fault)
    {
        var request=new FleetRequest("status",FleetProtocol.Nonce(),Guid.Empty,0,Guid.Empty,"");string json=JsonSerializer.Serialize(request,FleetProtocol.Json);
        json=fault switch{"v1"=>json.Replace(FleetProtocol.Version,"authority-fleet.v1"),"missing-version"=>json.Replace(",\"protocol\":\"authority-fleet.v2\"",""),"duplicate"=>json[..^1]+",\"action\":\"drain\"}","unknown"=>json[..^1]+",\"nativePassed\":true}","oversized"=>new(' ',32769),"deep"=>new string('[',17)+"0"+new string(']',17),_=>"{\"mode\":3}"};
        Assert.ThrowsAny<Exception>(()=>FleetProtocol.Read<FleetRequest>(Encoding.UTF8.GetBytes(json)));
    }
    [Fact] public void Exact_THS12C_fixture_hashes_and_binding_decode_with_both_named_policies()
    {
        string folder=Path.Combine(AppContext.BaseDirectory,"Fixtures/SvsRefillV1");using var manifest=JsonDocument.Parse(File.ReadAllText(Path.Combine(folder,"MANIFEST.json")));
        foreach(var file in manifest.RootElement.GetProperty("files").EnumerateObject())Assert.Equal(file.Value.GetString(),Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Path.Combine(folder,file.Name)))).ToLowerInvariant());
        var binding=FleetProtocol.Read<FleetBinding>(File.ReadAllBytes(Path.Combine(folder,"fleet-binding-v2.json")));binding.Validate();
        Assert.Equal(FleetPolicyHashes.Database,binding.DatabasePolicyHash);Assert.Equal(FleetPolicyHashes.Cache,binding.CachePolicyHash);Assert.Contains(binding.Participants,x=>x.Kind=="SVS");
        var prepare=FleetProtocol.Read<FleetRequest>(File.ReadAllBytes(Path.Combine(folder,"fleet-prepare-v2.json")));Assert.Equal(FleetProtocol.Digest(binding),FleetProtocol.Digest(prepare.Binding));
        var rejection=FleetProtocol.Read<FleetReply>(File.ReadAllBytes(Path.Combine(folder,"fleet-rejection-v2.json")));Assert.Equal("SVS",rejection.Kind);Assert.Equal(4,rejection.Isolation!.Rejected.Length);
    }
    [Fact] public async Task Boot_generation_binding_and_single_use_prepare_token_are_enforced_without_native_gate()
    {
        var s=CoherentHostTests.Settings(fixture);using var authority=new CoherentHostTests.RpcResourcesOwner();await using var resources=new CoherentResources(s,new CoherentHostTests.Database(authority.Value),new CoherentHostTests.Cache(s,authority.Value));
        var gate=resources.Gate;var status=gate.Reply(FleetProtocol.Nonce());var b=CoherentHostTests.Binding(s,resources);
        var request=CoherentHostTests.Request("prepare",status,b);int verified=0;
        await Assert.ThrowsAsync<InvalidOperationException>(()=>gate.PrepareAsync(request with{BootId=Guid.NewGuid()},(_,_)=>Task.CompletedTask,TestContext.Current.CancellationToken));
        string prepared=await gate.PrepareAsync(request,(_,_)=>{verified++;return Task.CompletedTask;},TestContext.Current.CancellationToken);
        await Assert.ThrowsAsync<InvalidOperationException>(()=>gate.ActivateAsync(request with{Prepared="foreign"},(_,_)=>Task.CompletedTask,TestContext.Current.CancellationToken));
        await gate.ActivateAsync(request with{Prepared=prepared},(_,_)=>{verified++;return Task.CompletedTask;},TestContext.Current.CancellationToken);Assert.Equal(2,verified);
        Assert.Equal(FleetMode.CoherentAdmitted,gate.Mode);
        await Assert.ThrowsAsync<InvalidOperationException>(()=>gate.ActivateAsync(request with{Prepared=prepared},(_,_)=>Task.CompletedTask,TestContext.Current.CancellationToken));
        var restarted=new AuthorityFleetGate(s.Fleet!);Assert.Equal(FleetMode.Unadmitted,restarted.Mode);Assert.NotEqual(status.BootId,restarted.Reply(FleetProtocol.Nonce()).BootId);
        await Assert.ThrowsAsync<InvalidOperationException>(()=>restarted.PrepareAsync(request with{BootId=restarted.BootId},(_,_)=>Task.CompletedTask,TestContext.Current.CancellationToken));
    }
    [Theory][InlineData("missing")][InlineData("duplicate")][InlineData("wrong-purpose")][InlineData("wrong-kind")]
    public void Isolation_inventory_requires_all_four_exact_named_credentials(string fault)
    {
        FleetIdentity[] identities=[new("validator","SQL","validator"),new("refiller","SQL","refiller"),new("cache-reader","Cache","svs-reader"),new("cache-refiller","Cache","svs-refiller")];
        identities=fault switch{"missing"=>identities[..3],"duplicate"=>[identities[0],identities[0],identities[2],identities[3]],"wrong-purpose"=>[identities[0] with{Purpose="app"},..identities[1..]],_=>[identities[0] with{Kind="Cache"},..identities[1..]]};
        Assert.Throws<InvalidOperationException>(()=>FleetProtocol.Identities("SVS",identities));
    }
}
