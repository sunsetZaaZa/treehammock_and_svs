using Microsoft.Extensions.Options;
using treehammock.Rigging.Config;
namespace treehammock.Rigging.Fleet;
// A restart ALWAYS starts unadmitted. Only the private authenticated control path
// may prepare/activate a binding checked against the durable control transaction.
public sealed class AuthorityFleetGate
{
 private readonly object _sync=new();private readonly AuthorityFleetSettings _settings;
 private FleetMode _mode=FleetMode.Unadmitted;private FleetBinding? _binding,_pending;
 private string? _prepared;private long _generation;private Guid _barrier;private string _inventory="";
 private int _active;private TaskCompletionSource _empty=Completed();
 private readonly TaskCompletionSource _admitted=new(TaskCreationOptions.RunContinuationsAsynchronously);
 internal Task WaitForAdmissionAsync(CancellationToken token)=>_admitted.Task.WaitAsync(token);
 internal Guid BootId { get; }=Guid.NewGuid();
 internal string Instance=>_settings.InstanceId;
 internal Guid Realm=>_settings.Realm;
 public FleetMode Mode {get{lock(_sync)return _mode;}}
 internal AuthorityFleetGate(AuthorityFleetSettings settings)
 {
  System.ComponentModel.DataAnnotations.Validator.ValidateObject(settings,new(settings),true);_settings=new AuthorityFleetSettings{InstanceId=settings.InstanceId,Realm=settings.Realm,CheckpointPath=settings.CheckpointPath};
  if(File.Exists(settings.CheckpointPath))
  {
   if(new FileInfo(settings.CheckpointPath).Length>4096)throw new InvalidOperationException("Invalid fleet checkpoint.");
   var saved=System.Text.Json.JsonSerializer.Deserialize<Checkpoint>(File.ReadAllText(settings.CheckpointPath),FleetProtocol.Json)??throw new InvalidOperationException();
   if(saved.Realm!=settings.Realm||saved.Instance!=settings.InstanceId||saved.Generation<0)throw new InvalidOperationException("Fleet checkpoint identity mismatch.");
   _generation=saved.Generation;_barrier=saved.Barrier;_inventory=saved.InventoryHash;
  }
 }
 private static TaskCompletionSource Completed(){var t=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);t.SetResult();return t;}
 internal IDisposable Enter()
 {
  lock(_sync){if(_mode is not (FleetMode.DBOnlyIsolated or FleetMode.CoherentAdmitted))throw new InvalidOperationException("Fleet instance is not serving.");if(_active++==0)_empty=new(TaskCreationOptions.RunContinuationsAsynchronously);return new Lease(this);}
 }
 internal void RequireWrite(){lock(_sync)if(_mode is not (FleetMode.DBOnlyIsolated or FleetMode.CoherentAdmitted))throw new InvalidOperationException("Authority fleet is quarantined.");}
 internal bool Current(FleetBinding binding){lock(_sync)return ReferenceEquals(_binding,binding)&&_mode==binding.Mode;}
 internal FleetBinding? ServingBinding(){lock(_sync)return _mode is FleetMode.CoherentAdmitted or FleetMode.DBOnlyIsolated?_binding:null;}
 internal FleetBinding Binding(){lock(_sync)return _binding??throw new InvalidOperationException("No fleet admission.");}
 internal void Quarantine(){lock(_sync){_mode=FleetMode.Quarantined;_binding=null;_pending=null;_prepared=null;}}
 internal async Task DrainAsync(FleetRequest request,Func<CancellationToken,Task> closeWriter,CancellationToken token)
 {
  Task empty;
  lock(_sync)
  {
   Check(request);if(request.Generation<_generation||request.Generation==_generation&&(_barrier!=request.Barrier||_inventory!=request.InventoryHash))throw new InvalidOperationException("Stale fleet barrier.");
   _mode=FleetMode.Quarantined;_binding=null;_pending=null;_prepared=null;_generation=request.Generation;_barrier=request.Barrier;_inventory=request.InventoryHash;
   Save();empty=_empty.Task;
  }
  // Stop admission before disconnecting publication and before awaiting readers.
  await closeWriter(token);await empty.WaitAsync(token);
 }
 internal async Task<string> PrepareAsync(FleetRequest request,Func<FleetBinding,CancellationToken,Task> verify,CancellationToken token)
 {
  FleetBinding binding=request.Binding??throw new InvalidOperationException("Missing fleet binding.");binding.Validate();
  lock(_sync){Check(request);if(_mode is not (FleetMode.Unadmitted or FleetMode.Quarantined)||_active!=0||binding.Realm!=Realm||binding.Generation!=request.Generation||binding.Barrier!=request.Barrier||binding.InventoryHash!=request.InventoryHash||request.Generation<=_generation)throw new InvalidOperationException("Fleet preparation rejected.");}
  await verify(binding,token);
  lock(_sync)
  {
   Check(request);if(_mode is not (FleetMode.Unadmitted or FleetMode.Quarantined)||_active!=0||request.Generation<=_generation)throw new InvalidOperationException("Concurrent fleet transition.");
   _generation=request.Generation;_barrier=request.Barrier;_inventory=request.InventoryHash;_pending=binding;_prepared=FleetProtocol.Nonce();Save();return _prepared;
  }
 }
 internal async Task ActivateAsync(FleetRequest request,Func<FleetBinding,CancellationToken,Task> verify,CancellationToken token)
 {
  FleetBinding binding;
  lock(_sync){Check(request);binding=_pending??throw new InvalidOperationException("No prepared fleet binding.");if(request.Generation!=_generation||request.Barrier!=_barrier||request.InventoryHash!=_inventory||request.Prepared!=_prepared)throw new InvalidOperationException("Foreign fleet activation.");}
  await verify(binding,token);
  lock(_sync){Check(request);if(!ReferenceEquals(_pending,binding)||request.Prepared!=_prepared)throw new InvalidOperationException("Fleet preparation changed.");_binding=binding;_mode=binding.Mode;_pending=null;_prepared=null;_admitted.TrySetResult();}
 }
 internal FleetReply Reply(string nonce)
 {lock(_sync)return new(FleetProtocol.Version,Instance,"TreeHammock",BootId,nonce,_generation,_barrier,_inventory,_mode,_active,_prepared,Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(treehammock.Services.DatabaseRoleBoundary.Policy))),CachePolicyHash:FleetPolicyHashes.Cache);}
 private void Check(FleetRequest r){if(r.Protocol!=FleetProtocol.Version||r.BootId!=BootId||r.Generation<1||r.Barrier==Guid.Empty||!FleetProtocol.Hash(r.Nonce)||!FleetProtocol.Hash(r.InventoryHash))throw new InvalidOperationException("Invalid fleet challenge.");}
 private sealed record Checkpoint(Guid Realm,string Instance,long Generation,Guid Barrier,string InventoryHash);
 private void Save()
 {
  var path=_settings.CheckpointPath;var directory=Path.GetDirectoryName(path)!;Directory.CreateDirectory(directory);string temp=path+"."+Guid.NewGuid().ToString("N")+".tmp";
  try{using(var file=new FileStream(temp,FileMode.CreateNew,FileAccess.Write,FileShare.None,4096,FileOptions.WriteThrough)){System.Text.Json.JsonSerializer.Serialize(file,new Checkpoint(Realm,Instance,_generation,_barrier,_inventory),FleetProtocol.Json);file.Flush(true);}File.Move(temp,path,true);}
  catch{_mode=FleetMode.Quarantined;_binding=null;_pending=null;_prepared=null;throw;}
  finally{if(File.Exists(temp))File.Delete(temp);}
 }
 private sealed class Lease(AuthorityFleetGate gate):IDisposable
 {
  private AuthorityFleetGate? _gate=gate;
  public void Dispose(){var g=Interlocked.Exchange(ref _gate,null);if(g is null)return;lock(g._sync)if(--g._active==0)g._empty.TrySetResult();}
 }
 public override string ToString()=>nameof(AuthorityFleetGate);
}
