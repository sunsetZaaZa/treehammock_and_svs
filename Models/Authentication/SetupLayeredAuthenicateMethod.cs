using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;

using treehammock.RiggingSupport.Enum;

namespace treehammock.Models.Authentication;

public class SetupLayeredAuthenticateMethodRequest : IValidatableObject
{
    public const int MaxContactLength = 320;

        [SetsRequiredMembers]
    public SetupLayeredAuthenticateMethodRequest()
    {
        method = TwoFactorAuthMethod.NONE;
        contact = string.Empty;
        countryCode = null;
        required = true;
    }

[SetsRequiredMembers]
    public SetupLayeredAuthenticateMethodRequest(TwoFactorAuthMethod method, string contact, short? countryCode, bool required)
    {
        (this.method, this.contact, this.countryCode, this.required) = (method, contact, countryCode, required);
    }

    [EnumDataType(typeof(TwoFactorAuthMethod))]
    public TwoFactorAuthMethod method { get; set; } = TwoFactorAuthMethod.NONE;

    [Required(AllowEmptyStrings = false)]
    [StringLength(MaxContactLength)]
    public string contact { get; set; } = string.Empty;

    [Range(1, short.MaxValue)]
    public short? countryCode { get; set; }

    public bool required { get; set; }
    public Guid? expectedEnrollmentId { get; set; }
    public long? expectedVersion { get; set; }

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (expectedEnrollmentId.HasValue != expectedVersion.HasValue || expectedEnrollmentId == Guid.Empty || expectedVersion is <= 0 or > 9007199254740991)
            yield return new ValidationResult("Replacement requires the exact pending enrollment ID and version.", [nameof(expectedEnrollmentId), nameof(expectedVersion)]);
        if (method == TwoFactorAuthMethod.NONE)
        {
            yield return new ValidationResult(
                "A supported two-factor method is required.",
                new[] { nameof(method) });
        }
    }
}

public class SetupLayeredAuthenticateMethodResponse
{
    [SetsRequiredMembers]
    public SetupLayeredAuthenticateMethodResponse(bool status)
    {
        this.status = status;
    }

    public required bool status { get; set; }
    public Guid? enrollmentId { get; set; }
    public long? setupVersion { get; set; }
}

public class VerifyLayeredAuthenticateMethodRequest : IValidatableObject
{
    public const int MinCodeLength = 1;
    public const int MaxCodeLength = 128;

        [SetsRequiredMembers]
    public VerifyLayeredAuthenticateMethodRequest()
    {
        method = TwoFactorAuthMethod.NONE;
        codeKey = string.Empty;
    }

[SetsRequiredMembers]
    public VerifyLayeredAuthenticateMethodRequest(TwoFactorAuthMethod method, string codeKey)
    {
        (this.method, this.codeKey) = (method, codeKey);
    }

    [EnumDataType(typeof(TwoFactorAuthMethod))]
    public TwoFactorAuthMethod method { get; set; } = TwoFactorAuthMethod.NONE;

    [Required(AllowEmptyStrings = false)]
    [StringLength(MaxCodeLength, MinimumLength = MinCodeLength)]
    public string codeKey { get; set; } = string.Empty;
    public Guid enrollmentId { get; set; }
    public long setupVersion { get; set; }

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (enrollmentId == Guid.Empty || setupVersion is <= 0 or > 9007199254740991)
            yield return new ValidationResult("The pending enrollment ID and version are required.", [nameof(enrollmentId), nameof(setupVersion)]);
        if (method == TwoFactorAuthMethod.NONE)
        {
            yield return new ValidationResult(
                "A supported two-factor method is required.",
                new[] { nameof(method) });
        }
    }
}
