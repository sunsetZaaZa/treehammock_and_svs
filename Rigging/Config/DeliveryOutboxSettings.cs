using System.ComponentModel.DataAnnotations;
namespace treehammock.Rigging.Config;

public sealed class DeliveryOutboxSettings : IValidatableObject
{
    public int ActiveKeyVersion { get; set; } = 1;
    public Dictionary<int,string> EncryptionKeys { get; set; } = new();
    [Range(5,120)] public int LeaseSeconds { get; set; } = 60;
    [Range(1,5)] public int MaxAttempts { get; set; } = 3;
    [Range(1,30)] public int PollSeconds { get; set; } = 2;
    [Range(1,30)] public int ProviderAttemptTimeoutSeconds { get; set; } = 10;
    [Range(1,5)] public int CancellationDrainSeconds { get; set; } = 2;
    [Range(1,8)] public int MaxConcurrentSends { get; set; } = 4;
    [Range(1,30)] public int ProviderTimeoutSeconds { get; set; } = 20;
    [Range(1,24)] public int PayloadRetentionHours { get; set; } = 24;
    public IEnumerable<ValidationResult> Validate(ValidationContext context)
    {
        if (!EncryptionKeys.ContainsKey(ActiveKeyVersion)) yield return new("Active delivery encryption key is required.");
        foreach (var pair in EncryptionKeys)
        {
            bool valid;
            try { valid = pair.Key > 0 && Convert.FromBase64String(pair.Value).Length == 32; } catch { valid = false; }
            if (!valid) yield return new("Delivery encryption keys must be versioned 32-byte base64 values.");
        }
        if (ProviderAttemptTimeoutSeconds > ProviderTimeoutSeconds) yield return new("Delivery attempt timeout cannot exceed the aggregate provider budget.");
        if (LeaseSeconds <= ProviderTimeoutSeconds + CancellationDrainSeconds + 10) yield return new("Delivery lease must cover the aggregate provider, cancellation drain, acquisition and commit budgets.");
    }
}
