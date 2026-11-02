using System.ComponentModel.DataAnnotations;

namespace treehammock.Rigging.Config;

public class LoginSettings : IValidatableObject
{
    [Range(1, 20)]
    public int PasswordRetryLimit { get; set; }

    [Range(1, 20)]
    public int TwoAuthRetryLimit { get; set; }

    [Range(0, 3600)]
    public int TwoFactorChallengeResendCooldownSeconds { get; set; } = 30;

    [Required]
    [MinLength(16)]
    public string TwoFactorChallengePepper { get; set; } = string.Empty;

    [Range(3, 10)]
    public int Argon2Iterations { get; set; } = 3;

    [Range(67108864, 134217728)]
    public int Argon2MemoryBytes { get; set; } = 67108864;

    // Recognize old configuration only to reject ambiguous units, never silently reinterpret it.
    public int? Argon2MemoryUsePer { get; set; }

    [Required]
    public PasswordWorkSettings PasswordWork { get; set; } = new();

    public IEnumerable<ValidationResult> Validate(ValidationContext context)
    {
        if (Argon2MemoryUsePer.HasValue)
            yield return new("Argon2MemoryUsePer is obsolete. Replace it with explicit Argon2MemoryBytes; 64 MiB is 67108864 bytes.", [nameof(Argon2MemoryUsePer)]);
        if (PasswordWork is null) yield break;
        if (Argon2MemoryBytes % 1024 != 0) yield return new("Argon2MemoryBytes must be a whole number of KiB expressed in bytes.");
        var errors = new List<ValidationResult>();
        Validator.TryValidateObject(PasswordWork, new(PasswordWork), errors, true);
        foreach (var error in errors) yield return error;
        if (Argon2MemoryBytes > PasswordWork.MaxEncodedMemoryBytes || Argon2Iterations > PasswordWork.MaxEncodedIterations)
            yield return new("Hash generation costs must fit accepted verification costs.");
    }
}

public sealed class PasswordWorkSettings : IValidatableObject
{
    [Range(1, 16)] public int MaxActiveOperations { get; set; } = 2;
    [Range(67108864, 1073741824)] public int MemoryBudgetBytes { get; set; } = 134217728;
    [Range(1, 16)] public int CpuBudget { get; set; } = 4;
    [Range(0, 128)] public int MaxQueuedOperations { get; set; } = 8;
    [Range(1, 5000)] public int QueueTimeoutMilliseconds { get; set; } = 250;
    [Range(67108864, 134217728)] public int MaxEncodedMemoryBytes { get; set; } = 134217728;
    [Range(3, 10)] public int MaxEncodedIterations { get; set; } = 10;
    [Range(1, 4)] public int MaxEncodedParallelism { get; set; } = 4;
    public IEnumerable<ValidationResult> Validate(ValidationContext context)
    {
        if (MemoryBudgetBytes < MaxEncodedMemoryBytes)
            yield return new("Every accepted hash must fit the password memory budget.");
        if (CpuBudget < MaxEncodedParallelism)
            yield return new("Every accepted hash must fit the password CPU budget.");
    }
}
