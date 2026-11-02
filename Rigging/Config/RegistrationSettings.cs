using System.ComponentModel.DataAnnotations;

namespace treehammock.Rigging.Config;

public class RegistrationSettings : IValidatableObject
{
    [Range(1, 128)]
    public uint MinUsernameLength { get; set; }

    [Range(1, 128)]
    public uint MaxUsernameLength { get; set; }

    [Range(1, 512)]
    public uint MinPasswordLength { get; set; }

    [Range(1, 512)]
    public uint MaxPasswordLength { get; set; }

    [Range(1, 1024)]
    public uint MaxEmailAddressLength { get; set; }

    [Range(1, 100)]
    public uint AccountMetaDataRetries { get; set; }

    [Range(0, 52)]
    public int VerifyAccountPeriodWeeks { get; set; }

    [Range(0, 365)]
    public int VerifyAccountPeriodDays { get; set; }

    [Range(0, 23)]
    public int VerifyAccountPeriodHours { get; set; }

    // Canonical public authority; deployment must supply an HTTPS origin.
    [Required] public string? PublicOrigin { get; set; }

    [Range(0, 52)]
    public int EmailChangeVerifyPeriodWeeks { get; set; }

    [Range(0, 365)]
    public int EmailChangeVerifyPeriodDays { get; set; } = 1;

    [Range(0, 23)]
    public int EmailChangeVerifyPeriodHours { get; set; }



    [Range(0, 52)]
    public int AccountDeleteTokenPeriodWeeks { get; set; }

    [Range(0, 365)]
    public int AccountDeleteTokenPeriodDays { get; set; } = 1;

    [Range(0, 23)]
    public int AccountDeleteTokenPeriodHours { get; set; }


    [Range(1, 1440)]
    public int DeleteRequestCooldownMinutes { get; set; } = 15;

    [Range(1, 168)]
    public int DeleteRequestWindowHours { get; set; } = 24;

    [Range(1, short.MaxValue)]
    public short DeleteMaxRequestsPerWindow { get; set; } = 8;

    [Range(1, short.MaxValue)]
    public short DeleteMaxFinalizeFailures { get; set; } = 5;

    [Range(1, 1440)]
    public int DeleteFinalizeLockoutMinutes { get; set; } = 30;

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (!treehammock.Rigging.Hosting.VerificationLinkBuilder.TryOrigin(PublicOrigin, out _))
            yield return new ValidationResult("RegistrationSettings PublicOrigin must be an absolute HTTP(S) origin without credentials, path, query or fragment.", new[] { nameof(PublicOrigin) });
        if (!HasPositivePeriod(VerifyAccountPeriodWeeks, VerifyAccountPeriodDays, VerifyAccountPeriodHours))
        {
            yield return new ValidationResult(
                "Account verification period must be greater than zero.",
                new[] { nameof(VerifyAccountPeriodWeeks), nameof(VerifyAccountPeriodDays), nameof(VerifyAccountPeriodHours) });
        }

        if (!HasPositiveEffectivePeriod(
            EmailChangeVerifyPeriodWeeks,
            EmailChangeVerifyPeriodDays,
            EmailChangeVerifyPeriodHours,
            VerifyAccountPeriodWeeks,
            VerifyAccountPeriodDays,
            VerifyAccountPeriodHours))
        {
            yield return new ValidationResult(
                "Email-change verification period must be greater than zero.",
                new[] { nameof(EmailChangeVerifyPeriodWeeks), nameof(EmailChangeVerifyPeriodDays), nameof(EmailChangeVerifyPeriodHours) });
        }

        if (!HasPositiveEffectivePeriod(
            AccountDeleteTokenPeriodWeeks,
            AccountDeleteTokenPeriodDays,
            AccountDeleteTokenPeriodHours,
            VerifyAccountPeriodWeeks,
            VerifyAccountPeriodDays,
            VerifyAccountPeriodHours))
        {
            yield return new ValidationResult(
                "Account-delete token period must be greater than zero.",
                new[] { nameof(AccountDeleteTokenPeriodWeeks), nameof(AccountDeleteTokenPeriodDays), nameof(AccountDeleteTokenPeriodHours) });
        }
    }

    private static bool HasPositiveEffectivePeriod(
        int weeks,
        int days,
        int hours,
        int fallbackWeeks,
        int fallbackDays,
        int fallbackHours)
    {
        return HasPositivePeriod(weeks, days, hours) ||
               (weeks == 0 && days == 0 && hours == 0 && HasPositivePeriod(fallbackWeeks, fallbackDays, fallbackHours));
    }

    private static bool HasPositivePeriod(int weeks, int days, int hours)
    {
        return weeks > 0 || days > 0 || hours > 0;
    }

}
