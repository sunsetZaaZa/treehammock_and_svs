using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;
using NodaTime;
using System.Diagnostics.CodeAnalysis;

namespace treehammock.Models.Account;

public sealed class AccountProfile
{
    public required string emailAddress { get; init; }
    public string? username { get; init; }
    public required Instant createdOn { get; init; }
    public required VerificationStatus verifyStatus { get; init; }
    public required Country country { get; init; }
    public treehammock.DataLayer.Entitlements.EntitlementProjection? entitlements { get; init; }
    public required FeatureSet features { get; init; }
    public required bool twoFactorEnabled { get; init; }
    public TwoFactorAuthConfiguration twoFactorAuthConfiguration { get; init; } = TwoFactorAuthConfiguration.NONE;
    public List<TwoFactorAuthMethod> twoFactorAuthMethods { get; init; } = [];
    public List<TwoFactorAuthConfiguration> availableTwoFactorAuthConfigurations { get; init; } = [];
}

public class AccountDetailsResponse
{
    [SetsRequiredMembers]
    public AccountDetailsResponse(HttpMessage result, AccountProfile? profile = null)
    {
        (this.result, this.profile) = (result, profile);
    }

    public required HttpMessage result { get; set; }
    public AccountProfile? profile { get; set; }
}
