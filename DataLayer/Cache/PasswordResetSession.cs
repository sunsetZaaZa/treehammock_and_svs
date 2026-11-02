using System.Diagnostics.CodeAnalysis;

using NodaTime;
using Newtonsoft.Json;

using treehammock.RiggingSupport.Enum;

namespace treehammock.DataLayer.Cache;

/// <summary>
/// Reset-specific state model introduced before runtime wiring so the SQL and endpoint PRs
/// can target one ordered proof contract instead of stretching the reset artifact ad hoc.
/// </summary>
[JsonObject(MemberSerialization.OptIn)]
public sealed class PasswordResetSession
{
    [JsonConstructor]
    [SetsRequiredMembers]
    public PasswordResetSession(
        Guid accountId,
        string resetAccessTokenHash,
        PasswordResetBootstrapProof bootstrapProof,
        IEnumerable<TwoFactorAuthConfiguration>? availableConfigurationsSnapshot,
        Instant createdOn,
        Instant expiresAt,
        PasswordResetSessionState state = PasswordResetSessionState.ResetTokenVerified,
        Guid? passwordResetRequestId = null)
    {
        this.passwordResetRequestId = passwordResetRequestId;
        this.accountId = accountId;
        this.resetAccessTokenHash = NormalizeRequiredTokenHash(resetAccessTokenHash);
        this.bootstrapProof = bootstrapProof;
        this.createdOn = createdOn;
        this.expiresAt = expiresAt;
        this.availableConfigurationsSnapshot = NormalizeConfigurations(availableConfigurationsSnapshot);
        this.state = state;
        selectedConfiguration = null;
        requiredMethods = [];
        completedMethods = [];
        currentExpectedMethod = null;
        challengeCodeHash = null;
        challengeExpiration = null;
        challengeAttempts = 0;
        challengeResends = 0;
        nextChallengeAllowedAt = null;
        selectedAt = null;
        twoFactorCompletedAt = null;
        passwordChangedAt = null;

        if (this.state == PasswordResetSessionState.ResetTokenVerified && this.availableConfigurationsSnapshot.Count > 0)
        {
            this.state = PasswordResetSessionState.TwoFactorSelectionRequired;
        }
    }

    [SetsRequiredMembers]
    public PasswordResetSession(
        Guid accountId,
        string resetAccessTokenHash,
        IEnumerable<TwoFactorAuthMethod>? verifiedMethods,
        PasswordResetBootstrapProof bootstrapProof,
        Instant createdOn,
        Instant expiresAt,
        Guid? passwordResetRequestId = null)
        : this(
            accountId,
            resetAccessTokenHash,
            bootstrapProof,
            PasswordResetTwoFactorConfigurationResolver.AvailableFromMethods(verifiedMethods, bootstrapProof),
            createdOn,
            expiresAt,
            passwordResetRequestId: passwordResetRequestId)
    {
    }

    [JsonProperty("passwordResetRequestId", Required = Required.AllowNull, Order = 0)]
    public Guid? passwordResetRequestId { get; set; }

    [JsonProperty("accountId", Required = Required.Always, Order = 1)]
    public required Guid accountId { get; set; }

    [JsonProperty("resetAccessTokenHash", Required = Required.Always, Order = 2)]
    public required string resetAccessTokenHash { get; set; }

    [JsonProperty("bootstrapProof", Required = Required.Always, Order = 3)]
    public required PasswordResetBootstrapProof bootstrapProof { get; set; }

    [JsonProperty("state", Required = Required.Always, Order = 4)]
    public required PasswordResetSessionState state { get; set; }

    [JsonProperty("availableConfigurationsSnapshot", Required = Required.Default, Order = 5)]
    public List<TwoFactorAuthConfiguration> availableConfigurationsSnapshot { get; set; } = [];

    [JsonProperty("selectedConfiguration", Required = Required.AllowNull, Order = 6)]
    public TwoFactorAuthConfiguration? selectedConfiguration { get; set; }

    [JsonProperty("requiredMethods", Required = Required.Default, Order = 7)]
    public List<TwoFactorAuthMethod> requiredMethods { get; set; } = [];

    [JsonProperty("completedMethods", Required = Required.Default, Order = 8)]
    public List<TwoFactorAuthMethod> completedMethods { get; set; } = [];

    [JsonProperty("currentExpectedMethod", Required = Required.AllowNull, Order = 9)]
    public TwoFactorAuthMethod? currentExpectedMethod { get; set; }

    [JsonProperty("challengeCodeHash", Required = Required.AllowNull, Order = 10)]
    public string? challengeCodeHash { get; set; }

    [JsonProperty("challengeExpiration", Required = Required.AllowNull, Order = 11)]
    public Instant? challengeExpiration { get; set; }

    [JsonProperty("challengeAttempts", Required = Required.Always, Order = 12)]
    public int challengeAttempts { get; set; }

    [JsonProperty("challengeResends", Required = Required.Always, Order = 13)]
    public int challengeResends { get; set; }

    [JsonProperty("nextChallengeAllowedAt", Required = Required.AllowNull, Order = 14)]
    public Instant? nextChallengeAllowedAt { get; set; }

    [JsonProperty("createdOn", Required = Required.Always, Order = 15)]
    public required Instant createdOn { get; set; }

    [JsonProperty("expiresAt", Required = Required.Always, Order = 16)]
    public required Instant expiresAt { get; set; }

    [JsonProperty("selectedAt", Required = Required.AllowNull, Order = 17)]
    public Instant? selectedAt { get; set; }

    [JsonProperty("twoFactorCompletedAt", Required = Required.AllowNull, Order = 18)]
    public Instant? twoFactorCompletedAt { get; set; }

    [JsonProperty("passwordChangedAt", Required = Required.AllowNull, Order = 19)]
    public Instant? passwordChangedAt { get; set; }

    [JsonProperty("sessionVersion")]
    public long sessionVersion { get; set; }

    [JsonProperty("challengeVersion")]
    public long challengeVersion { get; set; }

    [JsonProperty("factorPolicyVersion")]
    public string? factorPolicyVersion { get; set; }

    [JsonProperty("accountSecurityStamp")]
    public Guid? accountSecurityStamp { get; set; }

    [JsonIgnore]
    public string? bootstrapCodeHash { get; set; }

    [JsonIgnore]
    public PasswordResetTransition transition { get; set; } = PasswordResetTransition.Create;

    [JsonIgnore]
    public bool requiresTwoFactor => availableConfigurationsSnapshot.Count > 0;

    [JsonIgnore]
    public bool isSelectionRequired => state == PasswordResetSessionState.TwoFactorSelectionRequired && selectedConfiguration == null;

    [JsonIgnore]
    public bool isTwoFactorComplete => state == PasswordResetSessionState.TwoFactorComplete && remainingMethods.Count == 0;

    [JsonIgnore]
    public bool isPasswordChanged => state == PasswordResetSessionState.PasswordChanged && passwordChangedAt.HasValue;

    [JsonIgnore]
    public bool canChangePassword => (state == PasswordResetSessionState.ResetTokenVerified && !requiresTwoFactor) || isTwoFactorComplete;

    [JsonIgnore]
    public List<TwoFactorAuthMethod> remainingMethods => RemainingMethods();

    [JsonIgnore]
    public int requiredProofCount => requiredMethods.Count;

    [JsonIgnore]
    public int completedProofCount => completedMethods.Count;

    public bool CanSelectConfiguration(TwoFactorAuthConfiguration configuration)
    {
        return IsSelectableTwoFactorConfiguration(configuration)
            && availableConfigurationsSnapshot.Contains(configuration);
    }

    public void SelectConfiguration(TwoFactorAuthConfiguration configuration, Instant selectedAt)
    {
        if (!CanSelectConfiguration(configuration))
        {
            throw new ArgumentException("The requested two-factor configuration is not available for this password reset session.", nameof(configuration));
        }

        if (completedMethods.Count > 0 || state is PasswordResetSessionState.PasswordChanged or PasswordResetSessionState.Expired or PasswordResetSessionState.Failed)
            throw new ArgumentException("Reset proof progress and terminal state cannot be replaced.", nameof(configuration));
        transition = PasswordResetTransition.Select;
        List<TwoFactorAuthMethod> required = RequiredMethodsForConfiguration(configuration);
        if (required.Count == 0)
        {
            throw new ArgumentException("A selected password reset two-factor configuration must require at least one proof.", nameof(configuration));
        }

        selectedConfiguration = configuration;
        requiredMethods = required;
        completedMethods = [];
        this.selectedAt = selectedAt;
        twoFactorCompletedAt = null;
        // Attempts, resend budgets and cooldown remain attached to this authorization.
        challengeCodeHash = null;
        challengeExpiration = null;
        SetCurrentExpectedMethod(required[0]);
    }

    public void StartChallenge(string challengeCodeHash, Instant challengeExpiresAt, Instant nextChallengeAllowedAt)
    {
        if (!currentExpectedMethod.HasValue)
        {
            throw new InvalidOperationException("A password reset challenge cannot be issued until a current proof method is expected.");
        }

        if (transition != PasswordResetTransition.Select) transition = PasswordResetTransition.Resend;
        this.challengeCodeHash = NormalizeRequiredTokenHash(challengeCodeHash);
        challengeExpiration = challengeExpiresAt;
        challengeResends++;
        this.nextChallengeAllowedAt = nextChallengeAllowedAt;
    }

    public bool IsCurrentlyExpecting(TwoFactorAuthMethod method)
    {
        return currentExpectedMethod.HasValue && currentExpectedMethod.Value == method;
    }

    public void RegisterFailedChallengeAttempt()
    {
        transition = PasswordResetTransition.InvalidProof;
        challengeAttempts++;
    }

    public void MarkCurrentProofAccepted()
    {
        if (!currentExpectedMethod.HasValue)
        {
            throw new InvalidOperationException("There is no current password reset two-factor proof to accept.");
        }

        transition = PasswordResetTransition.ValidProof;
        if (!completedMethods.Contains(currentExpectedMethod.Value))
        {
            completedMethods.Add(currentExpectedMethod.Value);
        }

        ClearChallengeState();
        SetCurrentExpectedMethod(NextRequiredMethod());
    }

    public TwoFactorAuthMethod? NextRequiredMethod()
    {
        TwoFactorAuthMethod next = requiredMethods.FirstOrDefault(method => method != TwoFactorAuthMethod.NONE && !completedMethods.Contains(method));
        return next == TwoFactorAuthMethod.NONE ? null : next;
    }

    public void MarkTwoFactorComplete(Instant completedAt)
    {
        if (!requiresTwoFactor || selectedConfiguration is null)
        {
            throw new InvalidOperationException("A password reset session without a selected two-factor path cannot complete two-factor proof.");
        }

        if (remainingMethods.Count > 0)
        {
            throw new InvalidOperationException("A password reset session cannot complete two-factor proof while required proofs remain.");
        }

        state = PasswordResetSessionState.TwoFactorComplete;
        currentExpectedMethod = null;
        twoFactorCompletedAt = completedAt;
        ClearChallengeState();
    }

    public void MarkPasswordChanged(Instant changedAt)
    {
        if (!canChangePassword)
        {
            throw new InvalidOperationException("Password reset session is not authorized to change the password yet.");
        }

        state = PasswordResetSessionState.PasswordChanged;
        passwordChangedAt = changedAt;
        currentExpectedMethod = null;
        ClearChallengeState();
    }

    public void MarkExpired()
    {
        state = PasswordResetSessionState.Expired;
        currentExpectedMethod = null;
        ClearChallengeState();
    }

    public void MarkFailed()
    {
        state = PasswordResetSessionState.Failed;
        currentExpectedMethod = null;
        ClearChallengeState(resetResendCounter: true);
    }

    public void ResetToSelectionRequired()
    {
        selectedConfiguration = null;
        requiredMethods = [];
        completedMethods = [];
        currentExpectedMethod = null;
        selectedAt = null;
        twoFactorCompletedAt = null;
        ClearChallengeState(resetResendCounter: true);
        state = requiresTwoFactor
            ? PasswordResetSessionState.TwoFactorSelectionRequired
            : PasswordResetSessionState.ResetTokenVerified;
    }

    public List<TwoFactorAuthMethod> RemainingMethods()
    {
        return requiredMethods
            .Where(method => method != TwoFactorAuthMethod.NONE && !completedMethods.Contains(method))
            .ToList();
    }

    public static PasswordResetSessionState StateForMethod(TwoFactorAuthMethod method)
    {
        return method switch
        {
            TwoFactorAuthMethod.SMS_KEY => PasswordResetSessionState.AwaitingSmsCode,
            TwoFactorAuthMethod.EMAIL => PasswordResetSessionState.AwaitingEmailCode,
            TwoFactorAuthMethod.AUTHENTICATOR_APP => PasswordResetSessionState.AwaitingAuthenticatorCode,
            _ => PasswordResetSessionState.TwoFactorSelectionRequired
        };
    }

    public static List<TwoFactorAuthMethod> RequiredMethodsForConfiguration(TwoFactorAuthConfiguration configuration)
    {
        return configuration switch
        {
            TwoFactorAuthConfiguration.SMS => [TwoFactorAuthMethod.SMS_KEY],
            TwoFactorAuthConfiguration.EMAIL => [TwoFactorAuthMethod.EMAIL],
            TwoFactorAuthConfiguration.AUTHENTICATOR_APP => [TwoFactorAuthMethod.AUTHENTICATOR_APP],
            TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP => [TwoFactorAuthMethod.SMS_KEY, TwoFactorAuthMethod.AUTHENTICATOR_APP],
            TwoFactorAuthConfiguration.EMAIL_AND_AUTHENTICATOR_APP => [TwoFactorAuthMethod.EMAIL, TwoFactorAuthMethod.AUTHENTICATOR_APP],
            _ => []
        };
    }

    private static List<TwoFactorAuthConfiguration> NormalizeConfigurations(IEnumerable<TwoFactorAuthConfiguration>? configurations)
    {
        if (configurations is null)
        {
            return [];
        }

        var normalized = new List<TwoFactorAuthConfiguration>();
        foreach (TwoFactorAuthConfiguration configuration in configurations)
        {
            if (!IsSelectableTwoFactorConfiguration(configuration) || normalized.Contains(configuration))
            {
                continue;
            }

            normalized.Add(configuration);
        }

        return normalized;
    }

    private static bool IsSelectableTwoFactorConfiguration(TwoFactorAuthConfiguration configuration)
    {
        return configuration is TwoFactorAuthConfiguration.SMS
            or TwoFactorAuthConfiguration.EMAIL
            or TwoFactorAuthConfiguration.AUTHENTICATOR_APP
            or TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP
            or TwoFactorAuthConfiguration.EMAIL_AND_AUTHENTICATOR_APP;
    }

    private void SetCurrentExpectedMethod(TwoFactorAuthMethod? method)
    {
        currentExpectedMethod = method;
        state = method.HasValue
            ? StateForMethod(method.Value)
            : PasswordResetSessionState.TwoFactorSelectionRequired;
    }

    private void ClearChallengeState(bool resetResendCounter = false)
    {
        challengeCodeHash = null;
        challengeExpiration = null;
        // Counters and cooldown are monotonic for the authorization lifetime.
        _ = resetResendCounter;
    }

    private static string NormalizeRequiredTokenHash(string value)
    {
        string normalized = value.Trim();
        if (string.IsNullOrEmpty(normalized))
        {
            throw new ArgumentException("A password reset session token hash is required.", nameof(value));
        }

        return normalized;
    }
}
