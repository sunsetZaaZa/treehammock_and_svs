using System.Security.Cryptography;
using System.ComponentModel.DataAnnotations;

namespace treehammock.Rigging.Config;

public sealed class TotpSettings : IValidatableObject
{
    public const int MinimumSecretBytes = 20;
    public const int MaximumSecretBytes = 64;
    public const int MinimumPeriodSeconds = 15;
    public const int MaximumPeriodSeconds = 120;
    public const int RequiredProtectionKeyBytes = 32;
    public const int MinimumSetupIdBytes = 16;
    public const int MaximumSetupIdBytes = 64;


    [Required]
    public string Issuer { get; set; } = "Treehammock";

    [Range(6, 8)]
    public int Digits { get; set; } = 6;

    [Range(MinimumPeriodSeconds, MaximumPeriodSeconds)]
    public int PeriodSeconds { get; set; } = 30;

    [Range(0, 2)]
    public int AllowedClockSkewSteps { get; set; } = 1;

    [Required]
    public string HashAlgorithm { get; set; } = "SHA1";

    [Range(MinimumSecretBytes, MaximumSecretBytes)]
    public int SecretBytes { get; set; } = MinimumSecretBytes;

    [Required]
    public string ActiveProtectionKeyId { get; set; } = string.Empty;

    [Required]
    public Dictionary<string, string> ProtectionKeys { get; set; } = new(StringComparer.Ordinal);

    [Range(MinimumSetupIdBytes, MaximumSetupIdBytes)]
    public int SetupIdBytes { get; set; } = 32;

    [Range(1, 60)]
    public int SetupExpirationMinutes { get; set; } = 10;

    [Range(1, 10)]
    public short SetupMaxAttempts { get; set; } = 5;

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (string.IsNullOrWhiteSpace(Issuer))
        {
            yield return new ValidationResult("TotpSettings Issuer is required.", [nameof(Issuer)]);
        }

        if (Digits is not (6 or 7 or 8))
        {
            yield return new ValidationResult("TotpSettings Digits must be 6, 7, or 8.", [nameof(Digits)]);
        }

        if (!IsSupportedHashAlgorithm(HashAlgorithm))
        {
            yield return new ValidationResult("TotpSettings HashAlgorithm must be SHA1, SHA256, or SHA512.", [nameof(HashAlgorithm)]);
        }

        if (ProtectionKeys is null)
        { yield return new ValidationResult("TOTP key ring is required."); yield break; }
        if (ProtectionKeys.Count is < 1 or > 16 || string.IsNullOrWhiteSpace(ActiveProtectionKeyId) || !ProtectionKeys.ContainsKey(ActiveProtectionKeyId))
            yield return new ValidationResult("TOTP requires an active key ID in a deployment-injected key ring of 1–16 keys.");
        foreach (var entry in ProtectionKeys)
        {
            if (!System.Text.RegularExpressions.Regex.IsMatch(entry.Key, "^[A-Za-z0-9_-]{1,64}$") || !TryDecodeProtectionKey(entry.Value, out byte[] key))
                yield return new ValidationResult("TOTP key IDs or key material are invalid; published sample keys are forbidden.");
            else CryptographicOperations.ZeroMemory(key);
        }
    }

    public static bool IsSupportedHashAlgorithm(string? algorithm)
    {
        return string.Equals(algorithm, "SHA1", StringComparison.OrdinalIgnoreCase)
            || string.Equals(algorithm, "SHA256", StringComparison.OrdinalIgnoreCase)
            || string.Equals(algorithm, "SHA512", StringComparison.OrdinalIgnoreCase);
    }

    public static bool TryDecodeProtectionKey(string? encodedKey, out byte[] keyBytes)
    {
        keyBytes = [];
        if (string.IsNullOrWhiteSpace(encodedKey))
        {
            return false;
        }

        try
        {
            keyBytes = Convert.FromBase64String(encodedKey);
            if (keyBytes.Length == RequiredProtectionKeyBytes && !CryptographicOperations.FixedTimeEquals(keyBytes, "0123456789abcdef0123456789abcdef"u8) && keyBytes.Any(b => b != 0)) return true;
            CryptographicOperations.ZeroMemory(keyBytes); keyBytes = []; return false;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
