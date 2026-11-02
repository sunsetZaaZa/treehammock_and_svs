using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;

namespace treehammock.Rigging.Config;

public sealed class SecurityOperationSettings : IValidatableObject
{
    // Shared by every writer/recovery instance. Old keys stay readable until
    // every operation carrying that version has expired.
    public int ActiveKeyVersion { get; set; } = 1;
    [Required] public Dictionary<int, string> HmacKeys { get; set; } = new();
    [Range(1, 120)] public int ExecutionSeconds { get; set; } = 30;
    [Range(1, 10)] public int ReconciliationSeconds { get; set; } = 2;
    [Range(1, 30)] public int LockSeconds { get; set; } = 5;
    [Range(600, 604800)] public int RetentionSeconds { get; set; } = 86400;
    [Range(1, 1000)] public int CleanupBatchSize { get; set; } = 100;
    [Range(10, 3600)] public int CleanupIntervalSeconds { get; set; } = 60;
    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (HmacKeys is null) { yield return new ValidationResult("Security operations require a keyring."); yield break; }
        if (!HmacKeys.ContainsKey(ActiveKeyVersion) || ActiveKeyVersion < 1)
            yield return new ValidationResult("Security operations require the active shared HMAC key.");
        foreach (var pair in HmacKeys)
        {
            byte[]? key = null;
            try { key = Convert.FromBase64String(pair.Value); } catch (FormatException) { }
            if (pair.Key < 1 || key?.Length != 32)
                yield return new ValidationResult("Security operation HMAC keys must be 32-byte base64 values with positive versions.");
        }
        if (RetentionSeconds <= ExecutionSeconds + 120 || LockSeconds > ExecutionSeconds)
            yield return new ValidationResult("Operation retention must exceed execution/skew budgets; lock budget must fit execution.");
    }
    // Direct repository tests/tools get isolated, server-allocated operations.
    // Hosting always passes validated shared settings; this is never a host default.
    internal static SecurityOperationSettings Isolated() => new()
    {
        HmacKeys = new() { [1] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)) }
    };
}
