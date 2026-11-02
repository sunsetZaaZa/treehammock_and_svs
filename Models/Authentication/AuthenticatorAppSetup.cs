using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;

using NodaTime;

using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;

namespace treehammock.Models.Authentication;

public sealed class StartAuthenticatorAppSetupRequest : IValidatableObject
{
    public const int MaxLabelLength = 64;

    [StringLength(MaxLabelLength)]
    public string? label { get; set; }

    public bool required { get; set; } = true;
    public Guid? expectedEnrollmentId { get; set; }
    public long? expectedVersion { get; set; }

    [EnumDataType(typeof(TotpProviderType))]
    public TotpProviderType provider { get; set; } = TotpProviderType.LOCAL_RFC6238;

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (expectedEnrollmentId.HasValue != expectedVersion.HasValue || expectedEnrollmentId == Guid.Empty || expectedVersion is <= 0 or > 9007199254740991)
            yield return new ValidationResult("Replacement requires the exact pending enrollment ID and version.", [nameof(expectedEnrollmentId), nameof(expectedVersion)]);
        if (provider is not TotpProviderType.LOCAL_RFC6238)
        {
            yield return new ValidationResult(
                "provider must be LOCAL_RFC6238 until a managed-provider contract is implemented.",
                new[] { nameof(provider) });
        }

        if (!string.IsNullOrWhiteSpace(label) && label.Trim().Length > MaxLabelLength)
        {
            yield return new ValidationResult(
                $"label must be no longer than {MaxLabelLength} characters.",
                new[] { nameof(label) });
        }
    }
}

public sealed class StartAuthenticatorAppSetupResponse
{
    [SetsRequiredMembers]
    public StartAuthenticatorAppSetupResponse(HttpMessage result, bool status = false)
    {
        this.result = result;
        this.status = status;
    }

    public required bool status { get; set; }
    public required HttpMessage result { get; set; }
    public Guid? enrollmentId { get; set; }
    public long? setupVersion { get; set; }
    public string? setupId { get; set; }
    public string? otpauthUri { get; set; }
    public string? manualEntryKey { get; set; }
    public string? issuer { get; set; }
    public string? accountName { get; set; }
    public int? periodSeconds { get; set; }
    public int? digits { get; set; }
    public string? hashAlgorithm { get; set; }
    public TotpProviderType? provider { get; set; }
    public Instant? expiration { get; set; }
    public IReadOnlyList<string>? supportedAuthenticatorApps { get; set; }
}

public sealed class VerifyAuthenticatorAppSetupRequest
{
    public const int MaxSetupIdLength = 512;
    public const int MaxTotpCodeLength = 16;

        [SetsRequiredMembers]
    public VerifyAuthenticatorAppSetupRequest()
    {
        setupId = string.Empty;
        totpCode = string.Empty;
    }

[SetsRequiredMembers]
    public VerifyAuthenticatorAppSetupRequest(string setupId, string totpCode)
    {
        this.setupId = setupId;
        this.totpCode = totpCode;
    }

    [Required(AllowEmptyStrings = false)]
    [StringLength(MaxSetupIdLength)]
    public string setupId { get; set; } = string.Empty;

    [Required(AllowEmptyStrings = false)]
    [StringLength(MaxTotpCodeLength, MinimumLength = 1)]
    public string totpCode { get; set; } = string.Empty;
}

public sealed class VerifyAuthenticatorAppSetupResponse
{
    [SetsRequiredMembers]
    public VerifyAuthenticatorAppSetupResponse(HttpMessage result, bool status = false, string? accessToken = null)
    {
        this.result = result;
        this.status = status;
        this.accessToken = accessToken;
    }

    public required bool status { get; set; }
    public required HttpMessage result { get; set; }
    public string? accessToken { get; set; }
    public SessionCredential? session { get; set; }
}

public sealed class CancelAuthenticatorAppSetupRequest
{
    public const int MaxSetupIdLength = 512;

    [SetsRequiredMembers]
    public CancelAuthenticatorAppSetupRequest(string setupId)
    {
        this.setupId = setupId;
    }

    [Required(AllowEmptyStrings = false)]
    [StringLength(MaxSetupIdLength)]
    public string setupId { get; set; } = string.Empty;
}

public sealed class CancelAuthenticatorAppSetupResponse
{
    [SetsRequiredMembers]
    public CancelAuthenticatorAppSetupResponse(HttpMessage result, bool status = false)
    {
        this.result = result;
        this.status = status;
    }

    public required bool status { get; set; }
    public required HttpMessage result { get; set; }
}
