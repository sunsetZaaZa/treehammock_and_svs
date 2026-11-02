using System.ComponentModel.DataAnnotations;
namespace treehammock.Rigging.Config;
public sealed class ProviderHealthSettings
{
    public bool Enabled { get; set; } = true;
    public bool EmergencyEmailStop { get; set; }
    public bool EmergencySmsStop { get; set; }
    [Range(1,100)] public int FailureThreshold { get; set; } = 5;
    [Range(10,3600)] public int WindowSeconds { get; set; } = 300;
    [Range(1,900)] public int OpenSeconds { get; set; } = 60;
    [Range(45,120)] public int PermitSeconds { get; set; } = 45;
    [Range(1,128)] public int MaxInFlightPerRoute { get; set; } = 32;
    // Operator-owned labels identify the shared provider credential/account/region route, never an end user.
    [Required,RegularExpression("^[a-z0-9-]{1,64}$")] public string SmtpScope { get; set; } = "default";
    [Required,RegularExpression("^[a-z0-9-]{1,64}$")] public string TwilioScope { get; set; } = "default";
    [Required,RegularExpression("^[a-z0-9-]{1,64}$")] public string AwsSnsScope { get; set; } = "default";
}
