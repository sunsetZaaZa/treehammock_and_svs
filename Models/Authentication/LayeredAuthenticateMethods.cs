using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;

using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;

namespace treehammock.Models.Authentication;

public class LayeredAuthenticateMethodsRequest : IValidatableObject
{
        [SetsRequiredMembers]
    public LayeredAuthenticateMethodsRequest()
    {
        method = TwoFactorAuthMethod.NONE;
        destination = null;
    }

[SetsRequiredMembers]
    public LayeredAuthenticateMethodsRequest(TwoFactorAuthMethod method, short? destination = null)
    {
        (this.method, this.destination) = (method, destination);
    }

    [EnumDataType(typeof(TwoFactorAuthMethod))]
    public TwoFactorAuthMethod method { get; set; } = TwoFactorAuthMethod.NONE;

    [Range(0, short.MaxValue)]
    public short? destination { get; set; }

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

public class SelectTwoFactorConfigurationRequest : IValidatableObject
{
    public const int MaxTwoFactorAccessTokenLength = 2048;

    [SetsRequiredMembers]
    public SelectTwoFactorConfigurationRequest()
    {
        configuration = TwoFactorAuthConfiguration.NONE;
        destination = null;
        twoFactorAccessToken = null;
    }

    [SetsRequiredMembers]
    public SelectTwoFactorConfigurationRequest(TwoFactorAuthConfiguration configuration, short? destination = null, string? twoFactorAccessToken = null)
    {
        (this.configuration, this.destination, this.twoFactorAccessToken) = (configuration, destination, twoFactorAccessToken);
    }

    [EnumDataType(typeof(TwoFactorAuthConfiguration))]
    public TwoFactorAuthConfiguration configuration { get; set; } = TwoFactorAuthConfiguration.NONE;

    [Range(0, short.MaxValue)]
    public short? destination { get; set; }

    [StringLength(MaxTwoFactorAccessTokenLength)]
    public string? twoFactorAccessToken { get; set; }

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (configuration is TwoFactorAuthConfiguration.NONE or TwoFactorAuthConfiguration.CUSTOM)
        {
            yield return new ValidationResult(
                "A selectable two-factor configuration is required.",
                new[] { nameof(configuration) });
        }
    }
}

public class LayeredAuthenticateMethodsResponse
{
    [SetsRequiredMembers]
    public LayeredAuthenticateMethodsResponse(bool outcome)
        : this(outcome, outcome ? HttpMessage.NONE : HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED, null, null, null)
    {
    }

    [SetsRequiredMembers]
    public LayeredAuthenticateMethodsResponse(
        bool outcome,
        HttpMessage result,
        TwoFactorAuthMethod? method = null,
        string? challengeExpiration = null,
        short? chosenDestination = null,
        TwoFactorAuthConfiguration? selectedConfiguration = null,
        TwoFactorAuthMethod? currentRequiredMethod = null,
        List<TwoFactorAuthMethod>? completedTwoFactorAuthMethods = null,
        List<TwoFactorAuthMethod>? remainingTwoFactorAuthMethods = null,
        List<TwoFactorAuthConfiguration>? availableTwoFactorAuthConfigurations = null)
    {
        (this.outcome, this.result, this.method, this.challengeExpiration, this.chosenDestination, this.selectedConfiguration, this.currentRequiredMethod, this.completedTwoFactorAuthMethods, this.remainingTwoFactorAuthMethods, this.availableTwoFactorAuthConfigurations) =
            (outcome, result, method, challengeExpiration, chosenDestination, selectedConfiguration, currentRequiredMethod, completedTwoFactorAuthMethods, remainingTwoFactorAuthMethods, availableTwoFactorAuthConfigurations);
    }

    public long? progressVersion { get; set; }
    public Guid? challengeId { get; set; }

    public required bool outcome { get; set; }
    public required HttpMessage result { get; set; }
    public TwoFactorAuthMethod? method { get; set; }
    public string? challengeExpiration { get; set; }
    public short? chosenDestination { get; set; }
    public TwoFactorAuthConfiguration? selectedConfiguration { get; set; }
    public TwoFactorAuthMethod? currentRequiredMethod { get; set; }
    public List<TwoFactorAuthMethod>? completedTwoFactorAuthMethods { get; set; }
    public List<TwoFactorAuthMethod>? remainingTwoFactorAuthMethods { get; set; }
    public List<TwoFactorAuthConfiguration>? availableTwoFactorAuthConfigurations { get; set; }
}
