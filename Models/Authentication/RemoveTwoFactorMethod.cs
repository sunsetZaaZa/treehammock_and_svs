using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;

using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;

namespace treehammock.Models.Authentication;

public sealed class RemoveTwoFactorMethodRequest : IValidatableObject
{
    [SetsRequiredMembers]
    public RemoveTwoFactorMethodRequest()
    {
        method = TwoFactorAuthMethod.NONE;
    }

    [SetsRequiredMembers]
    public RemoveTwoFactorMethodRequest(TwoFactorAuthMethod method)
    {
        this.method = method;
    }

    [EnumDataType(typeof(TwoFactorAuthMethod))]
    public TwoFactorAuthMethod method { get; set; } = TwoFactorAuthMethod.NONE;

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (method is TwoFactorAuthMethod.NONE)
        {
            yield return new ValidationResult(
                "A removable two-factor method is required.",
                new[] { nameof(method) });
        }
    }
}

public sealed class RemoveTwoFactorMethodResponse
{
    [SetsRequiredMembers]
    public RemoveTwoFactorMethodResponse(
        bool outcome,
        HttpMessage result,
        TwoFactorAuthMethod? removedMethod = null,
        List<TwoFactorAuthMethod>? twoFactorAuthMethods = null,
        List<TwoFactorAuthConfiguration>? availableTwoFactorAuthConfigurations = null)
    {
        this.outcome = outcome;
        this.result = result;
        this.removedMethod = removedMethod;
        this.twoFactorAuthMethods = twoFactorAuthMethods;
        this.availableTwoFactorAuthConfigurations = availableTwoFactorAuthConfigurations;
    }

    public required bool outcome { get; set; }
    public required HttpMessage result { get; set; }
    public TwoFactorAuthMethod? removedMethod { get; set; }
    public List<TwoFactorAuthMethod>? twoFactorAuthMethods { get; set; }
    public List<TwoFactorAuthConfiguration>? availableTwoFactorAuthConfigurations { get; set; }
}
