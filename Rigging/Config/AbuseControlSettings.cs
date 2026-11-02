using treehammock.Rigging.Abuse;
using System.ComponentModel.DataAnnotations;

namespace treehammock.Rigging.Config;

public sealed class AbuseControlSettings : IValidatableObject
{
    [Required]
    public SignupAbusePolicySettings Signup { get; set; } = new();

    public bool Enabled { get; set; } = true;

    [Required]
    public TwoFactorAbusePolicySettings TwoFactor { get; set; } = new();

    [Required]
    public DeliveryAbusePolicySettings Delivery { get; set; } = new();

    [Required]
    public FailureCooldownSettings FailureCooldown { get; set; } = new();

    [Required]
    public LoginAbusePolicySettings Login { get; set; } = new();

    [Required]
    public PasswordResetAbusePolicySettings PasswordReset { get; set; } = new();

    [Required]
    public AccountUnlockAbusePolicySettings AccountUnlock { get; set; } = new();

    [Required]
    public AccountDeleteAbusePolicySettings AccountDelete { get; set; } = new();

    [Required]
    public PublicTokenVerificationAbusePolicySettings PublicTokenVerification { get; set; } = new();

    [Required]
    public ActivationAbusePolicySettings Activation { get; set; } = new();

    [Required]
    public AuthenticatedMutationIdempotencySettings AuthenticatedMutationIdempotency { get; set; } = new();

    [Range(10, 5000)]
    public int DragonflyTimeoutMilliseconds { get; set; } = 250;

    public AbuseCounterFailureMode CounterFailureMode { get; set; } = AbuseCounterFailureMode.FailClosed;

    // Explicit policies opt into an equivalent SQL budget on every request, including healthy cache periods.
    public List<AbuseFeature> PostgreSqlFallbackPolicies { get; set; } = [];
    [Range(50, 5000)] public int PostgreSqlBudgetTimeoutMilliseconds { get; set; } = 1000;

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (!AbuseCounterPolicyCatalog.ValidConfiguration(this))
            yield return new ValidationResult("AbuseControlSettings:CounterFailureMode/PostgreSqlFallbackPolicies requires an explicit supported version-1 policy selection; unsupported fallback is forbidden.", [nameof(CounterFailureMode), nameof(PostgreSqlFallbackPolicies)]);

        foreach (ValidationResult result in ValidateNested(TwoFactor, nameof(TwoFactor)))
        {
            yield return result;
        }

        foreach (ValidationResult result in ValidateNested(Signup, nameof(Signup))) yield return result;

        foreach (ValidationResult result in ValidateNested(Delivery, nameof(Delivery)))
        {
            yield return result;
        }

        foreach (ValidationResult result in ValidateNested(FailureCooldown, nameof(FailureCooldown)))
        {
            yield return result;
        }

        foreach (ValidationResult result in ValidateNested(Login, nameof(Login)))
        {
            yield return result;
        }

        foreach (ValidationResult result in ValidateNested(PasswordReset, nameof(PasswordReset)))
        {
            yield return result;
        }

        foreach (ValidationResult result in ValidateNested(AccountUnlock, nameof(AccountUnlock)))
        {
            yield return result;
        }

        foreach (ValidationResult result in ValidateNested(AccountDelete, nameof(AccountDelete)))
        {
            yield return result;
        }

        foreach (ValidationResult result in ValidateNested(PublicTokenVerification, nameof(PublicTokenVerification)))
        {
            yield return result;
        }

        foreach (ValidationResult result in ValidateNested(Activation, nameof(Activation)))
        {
            yield return result;
        }

        foreach (ValidationResult result in ValidateNested(AuthenticatedMutationIdempotency, nameof(AuthenticatedMutationIdempotency)))
        {
            yield return result;
        }

        if (!Enum.IsDefined(CounterFailureMode))
        {
            yield return new ValidationResult(
                "AbuseControlSettings CounterFailureMode must be a supported value.",
                [nameof(CounterFailureMode)]);
        }
    }

    private static IEnumerable<ValidationResult> ValidateNested(object? value, string propertyName)
    {
        if (value is null)
        {
            yield return new ValidationResult(
                $"AbuseControlSettings {propertyName} policy is required.",
                [propertyName]);
            yield break;
        }

        var results = new List<ValidationResult>();
        bool valid = Validator.TryValidateObject(
            value,
            new ValidationContext(value),
            results,
            validateAllProperties: true);

        if (valid)
        {
            yield break;
        }

        foreach (ValidationResult result in results)
        {
            string message = string.IsNullOrWhiteSpace(result.ErrorMessage)
                ? $"AbuseControlSettings {propertyName} policy is invalid."
                : $"AbuseControlSettings {propertyName}: {result.ErrorMessage}";
            yield return new ValidationResult(message, result.MemberNames.Select(member => $"{propertyName}.{member}"));
        }
    }
}

public enum AbuseCounterFailureMode
{
    FailClosed = 0,
    RequirePostgreSqlBudgetV1 = 1
}

public sealed class TwoFactorAbusePolicySettings
{
    public bool Enabled { get; set; } = true;

    [Range(1, 20)]
    public int MaxAttemptsPerChallenge { get; set; } = 5;

    [Range(60, 3600)]
    public int ChallengeAttemptWindowSeconds { get; set; } = 600;

    [Range(0, 86400)]
    public int CooldownSecondsAfterExhaustion { get; set; } = 900;

    [Range(1, 20)]
    public int MaxSetupVerifyAttemptsPerAccount { get; set; } = 5;

    [Range(60, 3600)]
    public int SetupVerifyAttemptWindowSeconds { get; set; } = 600;

    [Range(0, 86400)]
    public int SetupVerifyCooldownSecondsAfterExhaustion { get; set; } = 900;
}

public sealed class DeliveryAbusePolicySettings
{
    public bool Enabled { get; set; } = true;

    [Range(1, 1000)]
    public int MaxEmailDeliveriesPerAccountPerHour { get; set; } = 5;

    [Range(1, 1000)]
    public int MaxSmsDeliveriesPerAccountPerHour { get; set; } = 3;

    [Range(1, 10000)]
    public int MaxEmailDeliveriesPerIpPerHour { get; set; } = 20;

    [Range(1, 10000)]
    public int MaxSmsDeliveriesPerIpPerHour { get; set; } = 10;

    [Range(0, 86400)]
    public int CooldownSecondsAfterRepeatedFailures { get; set; } = 900;
}

public sealed class FailureCooldownSettings
{
    public bool Enabled { get; set; } = true;

    [Range(1, 1000)]
    public int FailureThreshold { get; set; } = 5;

    [Range(60, 86400)]
    public int WindowSeconds { get; set; } = 900;

    [Range(0, 86400)]
    public int CooldownSeconds { get; set; } = 900;
}

public sealed class LoginAbusePolicySettings
{
    public bool Enabled { get; set; } = true;

    [Range(1, 1000)]
    public int MaxAttemptsPerAccountPerWindow { get; set; } = 10;

    [Range(1, 1000)]
    public int MaxAttemptsPerIdentifierPerWindow { get; set; } = 10;

    [Range(1, 10000)]
    public int MaxAttemptsPerIpPerWindow { get; set; } = 50;

    public bool CaptchaChallengeEnabled { get; set; } = false;

    [Range(1, 10000)]
    public int CaptchaChallengeAfterAttempts { get; set; } = 5;

    [Range(60, 86400)]
    public int WindowSeconds { get; set; } = 900;

    [Range(0, 86400)]
    public int CooldownSeconds { get; set; } = 900;
}

public sealed class PasswordResetAbusePolicySettings
{
    public bool Enabled { get; set; } = true;

    [Range(1, 1000)]
    public int MaxRequestsPerAccountPerHour { get; set; } = 3;

    [Range(1, 1000)]
    public int MaxRequestsPerIdentifierPerHour { get; set; } = 5;

    [Range(1, 10000)]
    public int MaxRequestsPerIpPerHour { get; set; } = 20;

    [Range(1, 1000)]
    public int MaxTokenVerificationAttemptsPerResetId { get; set; } = 5;

    [Range(60, 86400)]
    public int TokenVerificationAttemptWindowSeconds { get; set; } = 900;

    [Range(1, 1000)]
    public int MaxTwoFactorProofAttemptsPerResetId { get; set; } = 5;

    [Range(60, 86400)]
    public int TwoFactorProofAttemptWindowSeconds { get; set; } = 900;

    [Range(1, 1000)]
    public int MaxFinalizeAttemptsPerResetId { get; set; } = 5;

    [Range(60, 86400)]
    public int FinalizeAttemptWindowSeconds { get; set; } = 900;

    [Range(0, 86400)]
    public int CooldownSecondsAfterExhaustion { get; set; } = 900;
}

public sealed class AccountUnlockAbusePolicySettings
{
    public bool Enabled { get; set; } = true;

    [Range(1, 1000)]
    public int MaxVerifyAttemptsPerToken { get; set; } = 5;

    [Range(1, 10000)]
    public int MaxVerifyAttemptsPerIp { get; set; } = 25;

    [Range(60, 86400)]
    public int VerifyAttemptWindowSeconds { get; set; } = 900;

    [Range(0, 86400)]
    public int CooldownSecondsAfterExhaustion { get; set; } = 900;
}


public sealed class AccountDeleteAbusePolicySettings
{
    public bool Enabled { get; set; } = true;

    [Range(1, 1000)]
    public int MaxFinalizeAttemptsPerAccount { get; set; } = 5;

    [Range(1, 1000)]
    public int MaxFinalizeAttemptsPerToken { get; set; } = 5;

    [Range(60, 86400)]
    public int FinalizeAttemptWindowSeconds { get; set; } = 900;

    [Range(0, 86400)]
    public int CooldownSecondsAfterExhaustion { get; set; } = 900;
}


public sealed class ActivationAbusePolicySettings
{
    // Durable creation limits always apply; Enabled controls only the cache verification brake.
    [Range(1, 5)] public int MaxCreateRequestsPerAccount { get; set; } = 5;
    [Range(1, 5)] public int MaxCreateRequestsPerIdentifier { get; set; } = 5;
    [Range(1, 50)] public int MaxCreateRequestsPerIp { get; set; } = 50;
    [Range(900, 86400)] public int CreateWindowSeconds { get; set; } = 900;
    [Range(60, 86400)] public int CreateCooldownSeconds { get; set; } = 60;

    public bool Enabled { get; set; } = true;

    [Range(1, 1000)]
    public int MaxVerifyAttemptsPerAccount { get; set; } = 5;

    [Range(1, 1000)]
    public int MaxVerifyAttemptsPerIdentifier { get; set; } = 5;

    [Range(1, 10000)]
    public int MaxVerifyAttemptsPerIp { get; set; } = 50;

    [Range(60, 86400)]
    public int VerifyAttemptWindowSeconds { get; set; } = 900;

    [Range(0, 86400)]
    public int CooldownSecondsAfterExhaustion { get; set; } = 900;
}

public sealed class PublicTokenVerificationAbusePolicySettings
{
    public bool Enabled { get; set; } = true;

    [Range(1, 1000)]
    public int MaxVerifyAttemptsPerToken { get; set; } = 10;

    [Range(1, 10000)]
    public int MaxVerifyAttemptsPerIp { get; set; } = 100;

    [Range(60, 86400)]
    public int VerifyAttemptWindowSeconds { get; set; } = 900;

    [Range(0, 86400)]
    public int CooldownSecondsAfterExhaustion { get; set; } = 900;
}


public sealed class AuthenticatedMutationIdempotencySettings : IValidatableObject
{
    public bool Enabled { get; set; } = true;

    [Range(16, 128)]
    public int MinKeyLength { get; set; } = 16;

    [Range(16, 128)]
    public int MaxKeyLength { get; set; } = 128;

    [Range(1, 60)]
    public int TimeoutMilliseconds { get; set; } = 25;

    [Range(600, 900)]
    public int InProgressTtlSeconds { get; set; } = 600;

    [Range(600, 900)]
    public int CompletedTtlSeconds { get; set; } = 900;

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (MinKeyLength > MaxKeyLength)
        {
            yield return new ValidationResult(
                "AuthenticatedMutationIdempotency MinKeyLength must be less than or equal to MaxKeyLength.",
                [nameof(MinKeyLength), nameof(MaxKeyLength)]);
        }
    }
}

public sealed class SignupAbusePolicySettings
{
    [Range(1, 1000)] public int MaxAttemptsPerIp { get; set; } = 20;
    [Range(1, 1000)] public int MaxAttemptsPerIdentifier { get; set; } = 10;
    [Range(60, 86400)] public int WindowSeconds { get; set; } = 900;
}
