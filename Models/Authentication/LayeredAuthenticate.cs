using treehammock.RiggingSupport.Enum;
using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;

namespace treehammock.Models.Authentication;

public class LayeredAuthenticateRequest : IValidatableObject
{
    public const int MinCodeLength = 1;
    public const int MaxCodeLength = 128;

        [SetsRequiredMembers]
    public LayeredAuthenticateRequest()
    {
        codeKey = string.Empty;
        method = TwoFactorAuthMethod.NONE;
    }

[SetsRequiredMembers]
    public LayeredAuthenticateRequest(string codeKey, TwoFactorAuthMethod method)
    {
        (this.codeKey, this.method) = (codeKey, method);
    }

    [Required(AllowEmptyStrings = false)]
    [StringLength(MaxCodeLength, MinimumLength = MinCodeLength)]
    public string codeKey { get; set; } = string.Empty;

    [EnumDataType(typeof(TwoFactorAuthMethod))]
    public TwoFactorAuthMethod method { get; set; } = TwoFactorAuthMethod.NONE;

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (method == TwoFactorAuthMethod.NONE)
        {
            yield return new ValidationResult(
                "A supported two-factor method is required.",
                new[] { nameof(method) });
        }
    }
}

public class LayeredAuthenticateResponse
{
    [SetsRequiredMembers]
    public LayeredAuthenticateResponse(
        TwoFactorAuthOutcome result,
        string? accessToken = null,
        TwoFactorAuthConfiguration? selectedConfiguration = null,
        TwoFactorAuthMethod? currentRequiredMethod = null,
        List<TwoFactorAuthMethod>? completedTwoFactorAuthMethods = null,
        List<TwoFactorAuthMethod>? remainingTwoFactorAuthMethods = null)
    {
        (this.result, this.accessToken, this.selectedConfiguration, this.currentRequiredMethod, this.completedTwoFactorAuthMethods, this.remainingTwoFactorAuthMethods) =
            (result, accessToken, selectedConfiguration, currentRequiredMethod, completedTwoFactorAuthMethods, remainingTwoFactorAuthMethods);
    }

    public long? progressVersion { get; set; }
    public Guid? challengeId { get; set; }

    public required TwoFactorAuthOutcome result { get; set; }
    public string? accessToken { get; set; }
    public SessionCredential? session { get; set; }
    public TwoFactorAuthConfiguration? selectedConfiguration { get; set; }
    public TwoFactorAuthMethod? currentRequiredMethod { get; set; }
    public List<TwoFactorAuthMethod>? completedTwoFactorAuthMethods { get; set; }
    public List<TwoFactorAuthMethod>? remainingTwoFactorAuthMethods { get; set; }
}
