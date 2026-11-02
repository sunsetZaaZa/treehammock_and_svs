using System.ComponentModel.DataAnnotations;
using treehammock.Rigging.Fleet;
namespace treehammock.Rigging.Config;
// Presence configures the private control agent; it never grants serving admission.
public sealed class AuthorityFleetSettings:IValidatableObject
{
 public string InstanceId { get; set; }="";
 public Guid Realm { get; set; }
 public string CheckpointPath { get; set; }="";
 public string BindAddress { get; set; }="127.0.0.1";
 [Range(1024,65535)] public int Port { get; set; }=5444;
 public string ServerCertificatePath { get; set; }="";
 public string ServerCertificatePassword { get; set; }="";
 public string ControllerRootCertificatePath { get; set; }="";
 public string[] ControllerPins { get; set; }=[];
 [Range(100,30000)] public int DrainTimeoutMilliseconds { get; set; }=10000;
 public IEnumerable<ValidationResult> Validate(ValidationContext context)
 {
  if(!FleetProtocol.Name(InstanceId)||Realm==Guid.Empty||!Path.IsPathFullyQualified(CheckpointPath))yield return new("Explicit fleet identity, realm and private absolute checkpoint required.");
  if(!PrivateAuthorityAddress.IsPrivateAddress(BindAddress)||!Path.IsPathFullyQualified(ServerCertificatePath)||!Path.IsPathFullyQualified(ControllerRootCertificatePath))yield return new("Private address and absolute fleet TLS material paths required.");
  if(ControllerPins is null||ControllerPins.Length is <1 or >2||ControllerPins.Any(x=>!FleetProtocol.Hash(x))||ControllerPins.Distinct().Count()!=ControllerPins.Length)yield return new("Distinct controller pins required.");
 }
 public override string ToString()=>nameof(AuthorityFleetSettings);
}
