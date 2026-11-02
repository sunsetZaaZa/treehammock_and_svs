using System.Diagnostics.CodeAnalysis;
using System.Runtime.Serialization;

using NodaTime;
using Newtonsoft.Json;

using treehammock.RiggingSupport.Enum;
using treehammock.Rigging.Security;

namespace treehammock.DataLayer.Cache;

// Keyed/Indexed by hashed pre-auth access token within Redis.
// This is intentionally separate from ActiveSession so a password-only login
// cannot become a fully authenticated session until the second factor succeeds.
[JsonObject(MemberSerialization.OptIn)]
public class TwoFactorSession
{
    [JsonConstructor]
    [SetsRequiredMembers]
    public TwoFactorSession(Guid accountId, string webKey, byte[] preAuthRefreshToken, List<TwoFactorAuthMethod> methods,
                            List<string>? userAuthIds, List<string>? phoneNumbers, List<string>? phoneCountryCode,
                            List<string>? emailAddresses, short? chosenDestination, string? intraCodeKey,
                            short authenticatorAppUsage, short smsKeyUsage, short smsUsage,
                            Instant createdOn, Instant expiration, FeatureSet features, Instant? cutOff = null,
                            Guid? accountSecurityStamp = null, string? priorActiveAccessTokenHash = null)
    {
        (this.accountId, this.webKey, this.preAuthRefreshToken, this.methods, this.userAuthIds, this.phoneNumbers, this.phoneCountryCode, this.emailAddresses,
            this.chosenDestination, this.intraCodeKey, this.authenticatorAppUsage, this.smsKeyUsage, this.smsUsage, this.createdOn, this.expiration, this.features, this.cutOff, this.accountSecurityStamp) =
        (accountId, webKey, preAuthRefreshToken, methods, userAuthIds, phoneNumbers, phoneCountryCode, emailAddresses, chosenDestination, intraCodeKey,
            authenticatorAppUsage, smsKeyUsage, smsUsage, createdOn, expiration, features, cutOff, AccountSecurityStampGuard.Require(accountSecurityStamp));

        this.priorActiveAccessTokenHash = string.IsNullOrWhiteSpace(priorActiveAccessTokenHash) ? null : priorActiveAccessTokenHash;
        this.availableConfigurationsSnapshot = TwoFactorAuthConfigurationResolver.AvailableFromMethods(methods);
        this.selectedConfiguration = null;
        this.state = TwoFactorSessionState.SelectionRequired;
        this.requiredMethods = [];
        this.completedMethods = [];
        this.currentExpectedMethod = null;
        this.challengedMethod = null;
        this.challengeCodeHash = null;
        this.challengeExpiration = null;
        this.challengeProviderTransactionId = null;
        this.challengeAttempts = 0;
        this.challengeResends = 0;
        this.nextChallengeAllowedAt = null;
    }

    [SetsRequiredMembers]
    public TwoFactorSession(List<TwoFactorAuthMethod> methods, List<string>? userAuthIds, List<string>? phoneNumbers, List<string>? phoneCountryCode,
                            List<string>? emailAddresses, short? chosenDestination, string? intraCodeKey, short authenticatorAppUsage, short smsKeyUsage, short smsUsage,
                            Guid? accountSecurityStamp = null)
        : this(Guid.Empty, string.Empty, Array.Empty<byte>(), methods, userAuthIds, phoneNumbers, phoneCountryCode, emailAddresses, chosenDestination, intraCodeKey,
            authenticatorAppUsage, smsKeyUsage, smsUsage, SystemClock.Instance.GetCurrentInstant(), SystemClock.Instance.GetCurrentInstant(), FeatureSet.basic,
            accountSecurityStamp: accountSecurityStamp)
    {
    }

    [JsonProperty("accountId", Required = Required.Always, Order = 1)]
    public required Guid accountId { get; set; }

    [JsonProperty("webKey", Required = Required.Always, Order = 2)]
    public required string webKey { get; set; }

    [JsonProperty("preAuthRefreshToken", Required = Required.Always, Order = 3)]
    public required byte[] preAuthRefreshToken { get; set; }

    [JsonProperty("methods", Required = Required.Always, Order = 4)]
    public required List<TwoFactorAuthMethod> methods { get; set; } // sync'd in order via index

    [JsonProperty("userAuthIds", Required = Required.AllowNull, Order = 5)]
    public required List<string>? userAuthIds { get; set; } // sync'd in order via index

    [JsonProperty("phoneNumbers", Required = Required.AllowNull, Order = 6)]
    public required List<string>? phoneNumbers { get; set; } // sync'd in order via index

    [JsonProperty("phoneCountryCode", Required = Required.AllowNull, Order = 7)]
    public required List<string>? phoneCountryCode { get; set; } // sync'd in order via index

    [JsonProperty("emailAddresses", Required = Required.AllowNull, Order = 8)]
    public required List<string>? emailAddresses { get; set; } // sync'd in order via index

    [JsonProperty("chosenDestination", Required = Required.AllowNull, Order = 9)]
    public required short? chosenDestination { get; set; } // index into which one user has chosen to use

    [JsonProperty("intraCodeKey", Required = Required.AllowNull, Order = 10)]
    public required string? intraCodeKey { get; set; } // legacy challenge storage; prefer challengeCodeHash for new flows

    [JsonProperty("challengedMethod", Required = Required.AllowNull, Order = 11)]
    public TwoFactorAuthMethod? challengedMethod { get; set; }

    [JsonProperty("challengeCodeHash", Required = Required.AllowNull, Order = 12)]
    public string? challengeCodeHash { get; set; }

    [JsonProperty("challengeExpiration", Required = Required.AllowNull, Order = 13)]
    public Instant? challengeExpiration { get; set; }

    [JsonProperty("challengeProviderTransactionId", Required = Required.AllowNull, Order = 14)]
    public string? challengeProviderTransactionId { get; set; }

    [JsonProperty("challengeAttempts", Required = Required.Always, Order = 15)]
    public short challengeAttempts { get; set; }

    [JsonProperty("challengeResends", Required = Required.Always, Order = 16)]
    public short challengeResends { get; set; }

    [JsonProperty("nextChallengeAllowedAt", Required = Required.AllowNull, Order = 17)]
    public Instant? nextChallengeAllowedAt { get; set; }

    [JsonProperty("authenticatorAppUsage", Required = Required.Always, Order = 18)]
    public required short authenticatorAppUsage { get; set; }

    [JsonProperty("smsKeyUsage", Required = Required.Always, Order = 19)]
    public required short smsKeyUsage { get; set; }

    [JsonProperty("smsUsage", Required = Required.Always, Order = 20)]
    public required short smsUsage { get; set; }

    [JsonProperty("createdOn", Required = Required.Always, Order = 21)]
    public required Instant createdOn { get; set; }

    [JsonProperty("expiration", Required = Required.Always, Order = 22)]
    public required Instant expiration { get; set; }

    [JsonProperty("cutOff", Required = Required.AllowNull, Order = 23)]
    public Instant? cutOff { get; set; }

    [JsonProperty("features", Required = Required.Always, Order = 24)]
    public required FeatureSet features { get; set; }

    [JsonProperty("accountSecurityStamp", Required = Required.Always, Order = 25)]
    public required Guid accountSecurityStamp { get; set; }

    [JsonProperty("progressVersion", Required = Required.Always, Order = 33)]
    public long progressVersion { get; set; } = 1;
    [JsonProperty("challengeId", Required = Required.AllowNull, Order = 34)]
    public Guid? challengeId { get; set; }

    [OnDeserialized]
    internal void ValidateProofVersion(StreamingContext context)
    {
        if (progressVersion < 1 || progressVersion > treehammock.Rigging.Authorization.SessionProtocol.MaximumGeneration || challengeId == Guid.Empty)
            throw new ArgumentException("Invalid pending proof lineage.");
    }

    public void ApplyDurableProofState(TwoFactorSession current)
    {
        if (current.accountId != accountId || current.accountSecurityStamp != accountSecurityStamp || current.progressVersion < progressVersion || current.progressVersion > treehammock.Rigging.Authorization.SessionProtocol.MaximumGeneration)
            throw new ArgumentException("Invalid pending proof projection.");
        progressVersion = current.progressVersion;
        challengeId = current.challengeId;
        availableConfigurationsSnapshot = current.availableConfigurationsSnapshot;
        selectedConfiguration = current.selectedConfiguration;
        state = current.state;
        requiredMethods = current.requiredMethods;
        completedMethods = current.completedMethods;
        currentExpectedMethod = current.currentExpectedMethod;
        challengedMethod = current.challengedMethod;
        chosenDestination = current.chosenDestination;
        challengeCodeHash = current.challengeCodeHash;
        intraCodeKey = null;
        challengeExpiration = current.challengeExpiration;
        challengeProviderTransactionId = current.challengeProviderTransactionId;
        challengeAttempts = current.challengeAttempts;
        challengeResends = current.challengeResends;
        nextChallengeAllowedAt = current.nextChallengeAllowedAt;
    }

    /// <summary>
    /// Previous active access-token hash captured when a password re-login requiring 2FA
    /// must rotate an existing active session after the second factor succeeds.
    /// Null means the pending 2FA login started from an unauthenticated request and should create a new session.
    /// </summary>
    [JsonProperty("priorActiveAccessTokenHash", Required = Required.Default, Order = 26)]
    public string? priorActiveAccessTokenHash { get; set; }

    [JsonProperty("availableConfigurationsSnapshot", Required = Required.Default, Order = 27)]
    public List<TwoFactorAuthConfiguration> availableConfigurationsSnapshot { get; set; } = [];

    [JsonProperty("selectedConfiguration", Required = Required.AllowNull, Order = 28)]
    public TwoFactorAuthConfiguration? selectedConfiguration { get; set; }

    [JsonProperty("state", Required = Required.Default, Order = 29)]
    public TwoFactorSessionState state { get; set; } = TwoFactorSessionState.SelectionRequired;

    [JsonProperty("requiredMethods", Required = Required.Default, Order = 30)]
    public List<TwoFactorAuthMethod> requiredMethods { get; set; } = [];

    [JsonProperty("completedMethods", Required = Required.Default, Order = 31)]
    public List<TwoFactorAuthMethod> completedMethods { get; set; } = [];

    [JsonProperty("currentExpectedMethod", Required = Required.AllowNull, Order = 32)]
    public TwoFactorAuthMethod? currentExpectedMethod { get; set; }

    [JsonIgnore]
    public List<TwoFactorAuthMethod> remainingMethods => RemainingMethods();

    [JsonIgnore]
    public short requiredProofCount => ClampToShort(requiredMethods.Count);

    [JsonIgnore]
    public short completedProofCount => ClampToShort(completedMethods.Count);

    [JsonIgnore]
    public bool isSelectionRequired => state == TwoFactorSessionState.SelectionRequired && selectedConfiguration == null;

    [JsonIgnore]
    public bool isComplete => state == TwoFactorSessionState.Complete && remainingMethods.Count == 0;

    public bool CanSelectConfiguration(TwoFactorAuthConfiguration configuration)
    {
        return IsSelectableTwoFactorConfiguration(configuration)
            && availableConfigurationsSnapshot.Contains(configuration);
    }

    public void ResetToSelectionRequired()
    {
        selectedConfiguration = null;
        state = TwoFactorSessionState.SelectionRequired;
        requiredMethods = [];
        completedMethods = [];
        currentExpectedMethod = null;
        challengedMethod = null;
        challengeCodeHash = null;
        challengeExpiration = null;
        challengeProviderTransactionId = null;
        chosenDestination = null;
        intraCodeKey = null;
        challengeAttempts = 0;
        challengeResends = 0;
        nextChallengeAllowedAt = null;
    }

    public void SelectConfiguration(TwoFactorAuthConfiguration configuration, IEnumerable<TwoFactorAuthMethod> required)
    {
        if (!CanSelectConfiguration(configuration))
        {
            throw new ArgumentException("The requested two-factor configuration is not available for this pending session.", nameof(configuration));
        }

        List<TwoFactorAuthMethod> normalizedRequired = NormalizeMethodSequence(required);
        if (normalizedRequired.Count == 0)
        {
            throw new ArgumentException("A selected two-factor configuration must require at least one proof.", nameof(required));
        }

        selectedConfiguration = configuration;
        requiredMethods = normalizedRequired;
        completedMethods = [];
        SetCurrentExpectedMethod(normalizedRequired[0]);
        challengedMethod = null;
        challengeCodeHash = null;
        challengeExpiration = null;
        challengeProviderTransactionId = null;
        chosenDestination = null;
        intraCodeKey = null;
        challengeAttempts = 0;
        challengeResends = 0;
        nextChallengeAllowedAt = null;
    }

    public void SetCurrentExpectedMethod(TwoFactorAuthMethod? method)
    {
        currentExpectedMethod = method;
        state = method.HasValue
            ? StateForMethod(method.Value)
            : TwoFactorSessionState.SelectionRequired;
    }

    public void StartChallenge(TwoFactorAuthMethod method, short destination, Instant challengeExpiresAt, Instant nextChallengeAllowedAt)
    {
        selectedConfiguration ??= SingleMethodConfiguration(method);
        if (requiredMethods.Count == 0)
        {
            requiredMethods = [method];
        }

        SetCurrentExpectedMethod(method);
        challengedMethod = method;
        chosenDestination = destination;
        challengeExpiration = challengeExpiresAt;
        challengeAttempts = 0;
        challengeResends++;
        this.nextChallengeAllowedAt = nextChallengeAllowedAt;
    }

    public void ClearIssuedChallengeState(Instant? challengeExpiresAt, short attempts, short resends, Instant? nextAllowedAt)
    {
        challengedMethod = null;
        chosenDestination = null;
        challengeCodeHash = null;
        intraCodeKey = null;
        challengeProviderTransactionId = null;
        challengeExpiration = challengeExpiresAt;
        challengeAttempts = attempts;
        challengeResends = resends;
        nextChallengeAllowedAt = nextAllowedAt;
    }

    public bool IsCurrentlyExpecting(TwoFactorAuthMethod method)
    {
        return currentExpectedMethod.HasValue && currentExpectedMethod.Value == method;
    }

    public void MarkCurrentProofAccepted()
    {
        if (currentExpectedMethod.HasValue && !completedMethods.Contains(currentExpectedMethod.Value))
        {
            completedMethods.Add(currentExpectedMethod.Value);
        }
    }

    public TwoFactorAuthMethod? NextRequiredMethod()
    {
        TwoFactorAuthMethod next = requiredMethods.FirstOrDefault(method => method != TwoFactorAuthMethod.NONE && !completedMethods.Contains(method));
        return next == TwoFactorAuthMethod.NONE ? null : next;
    }

    public void MarkComplete()
    {
        state = TwoFactorSessionState.Complete;
        currentExpectedMethod = null;
        challengedMethod = null;
        challengeCodeHash = null;
        challengeExpiration = null;
        challengeProviderTransactionId = null;
        chosenDestination = null;
        intraCodeKey = null;
        nextChallengeAllowedAt = null;
    }

    public List<TwoFactorAuthMethod> RemainingMethods()
    {
        return requiredMethods
            .Where(method => method != TwoFactorAuthMethod.NONE && !completedMethods.Contains(method))
            .ToList();
    }

    public static TwoFactorSessionState StateForMethod(TwoFactorAuthMethod method)
    {
        return method switch
        {
            TwoFactorAuthMethod.SMS_KEY => TwoFactorSessionState.AwaitingSmsCode,
            TwoFactorAuthMethod.EMAIL => TwoFactorSessionState.AwaitingEmailCode,
            TwoFactorAuthMethod.AUTHENTICATOR_APP => TwoFactorSessionState.AwaitingAuthenticatorCode,
            _ => TwoFactorSessionState.SelectionRequired
        };
    }

    public static TwoFactorAuthConfiguration? SingleMethodConfiguration(TwoFactorAuthMethod method)
    {
        return method switch
        {
            TwoFactorAuthMethod.SMS_KEY => TwoFactorAuthConfiguration.SMS,
            TwoFactorAuthMethod.EMAIL => TwoFactorAuthConfiguration.EMAIL,
            TwoFactorAuthMethod.AUTHENTICATOR_APP => TwoFactorAuthConfiguration.AUTHENTICATOR_APP,
            _ => null
        };
    }

    private static bool IsSelectableTwoFactorConfiguration(TwoFactorAuthConfiguration configuration)
    {
        return configuration is TwoFactorAuthConfiguration.SMS
            or TwoFactorAuthConfiguration.EMAIL
            or TwoFactorAuthConfiguration.AUTHENTICATOR_APP
            or TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP
            or TwoFactorAuthConfiguration.EMAIL_AND_AUTHENTICATOR_APP;
    }

    private static List<TwoFactorAuthMethod> NormalizeMethodSequence(IEnumerable<TwoFactorAuthMethod> methods)
    {
        var normalized = new List<TwoFactorAuthMethod>();
        foreach (TwoFactorAuthMethod method in methods)
        {
            if (method == TwoFactorAuthMethod.NONE || normalized.Contains(method))
            {
                continue;
            }

            normalized.Add(method);
        }

        return normalized;
    }

    private static short ClampToShort(int count)
    {
        return (short)Math.Min(short.MaxValue, Math.Max(0, count));
    }
}
