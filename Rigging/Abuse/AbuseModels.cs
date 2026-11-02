namespace treehammock.Rigging.Abuse;

public enum AbuseFeature
{
    Login = 0,
    TwoFactorChallenge = 1,
    Delivery = 2,
    PasswordResetRequest = 3,
    PasswordResetFinalize = 4,
    AccountUnlock = 5,
    Activation = 6,
    TwoFactorSetup = 7,
    AccountDeleteFinalize = 8,
    PublicTokenVerification = 9,
    PasswordResetTokenVerification = 10,
    PasswordResetTwoFactorProof = 11,
    Signup = 12,
    Reauthentication = 13
}

public enum AbuseCounterDimension
{
    Account = 0,
    IpFingerprint = 1,
    IdentifierFingerprint = 2,
    Challenge = 3,
    Session = 4,
    Reset = 5,
    DeliveryMethod = 6,
    TokenFingerprint = 7
}

public enum AbuseDecisionStatus
{
    Allowed = 0,
    Denied = 1,
    Cooldown = 2,
    CounterUnavailable = 3
}

public sealed record SafeAbuseIdentifier
{
    public SafeAbuseIdentifier(string kind, int length, string fingerprint)
    {
        if (string.IsNullOrWhiteSpace(kind))
        {
            throw new ArgumentException("Safe abuse identifier kind is required.", nameof(kind));
        }

        if (length < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(length), "Safe abuse identifier length cannot be negative.");
        }

        if (string.IsNullOrWhiteSpace(fingerprint))
        {
            throw new ArgumentException("Safe abuse identifier fingerprint is required.", nameof(fingerprint));
        }

        Kind = NormalizeSegment(kind, nameof(kind));
        Length = length;
        Fingerprint = NormalizeSegment(fingerprint, nameof(fingerprint));
    }

    public string Kind { get; }

    public int Length { get; }

    public string Fingerprint { get; }

    private static string NormalizeSegment(string value, string argumentName)
    {
        string normalized = value.Trim().ToLowerInvariant();
        if (normalized.Contains(':') || normalized.Contains('/') || normalized.Any(char.IsWhiteSpace))
        {
            throw new ArgumentException("Safe abuse identifier segments cannot contain separators or whitespace.", argumentName);
        }

        return normalized;
    }
}

public sealed record AbuseCounterKey
{
    public AbuseCounterKey(AbuseFeature feature, AbuseCounterDimension dimension, string safeId)
    {
        if (string.IsNullOrWhiteSpace(safeId))
        {
            throw new ArgumentException("A safe abuse counter identifier is required.", nameof(safeId));
        }

        Feature = feature;
        Dimension = dimension;
        SafeId = NormalizeSegment(safeId, nameof(safeId));
    }

    public AbuseFeature Feature { get; }

    public AbuseCounterDimension Dimension { get; }

    public string SafeId { get; }

    public string Value => $"abuse:{ToKeySegment(Feature)}:{ToKeySegment(Dimension)}:{SafeId}";

    public string CooldownValue => $"abuse:cooldown:{ToKeySegment(Feature)}:{ToKeySegment(Dimension)}:{SafeId}";

    public override string ToString()
    {
        return Value;
    }

    private static string ToKeySegment<TEnum>(TEnum value)
        where TEnum : struct, Enum
    {
        return value.ToString().Trim().ToLowerInvariant();
    }

    private static string NormalizeSegment(string value, string argumentName)
    {
        string normalized = value.Trim().ToLowerInvariant();
        if (normalized.Contains(':') || normalized.Contains('/') || normalized.Any(char.IsWhiteSpace))
        {
            throw new ArgumentException("Abuse counter key segments cannot contain separators or whitespace.", argumentName);
        }

        return normalized;
    }
}

public sealed record AbuseCounterLimit
{
    public AbuseCounterLimit(int maxAttempts, TimeSpan window, TimeSpan? cooldown = null)
    {
        if (maxAttempts <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxAttempts), "Max attempts must be greater than zero.");
        }

        if (window <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(window), "Counter window must be greater than zero.");
        }

        if (cooldown is not null && cooldown < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(cooldown), "Cooldown cannot be negative.");
        }

        // Server arithmetic remains bounded; fractional milliseconds round up, never down to zero.
        MaxAttempts = Math.Min(maxAttempts, 1_000_000);
        Window = TimeSpan.FromMilliseconds(Math.Clamp(Math.Ceiling(window.TotalMilliseconds), 1, 86_400_000));
        Cooldown = cooldown is null ? null : cooldown == TimeSpan.Zero ? TimeSpan.Zero
            : TimeSpan.FromMilliseconds(Math.Clamp(Math.Ceiling(cooldown.Value.TotalMilliseconds), 1, 86_400_000));
    }

    public int MaxAttempts { get; }

    public TimeSpan Window { get; }

    public TimeSpan? Cooldown { get; }
}

public sealed record AbuseDecision(
    AbuseDecisionStatus Status,
    string? ReasonCode = null,
    TimeSpan? RetryAfter = null)
{
    public bool Allowed => Status == AbuseDecisionStatus.Allowed;

    public static AbuseDecision Allow()
    {
        return new AbuseDecision(AbuseDecisionStatus.Allowed);
    }

    public static AbuseDecision Deny(string reasonCode, TimeSpan? retryAfter = null)
    {
        return new AbuseDecision(AbuseDecisionStatus.Denied, reasonCode, retryAfter);
    }

    public static AbuseDecision Cooldown(string reasonCode, TimeSpan retryAfter)
    {
        return new AbuseDecision(AbuseDecisionStatus.Cooldown, reasonCode, retryAfter);
    }
}

public enum CounterStoreAvailability { Available, Unavailable }

public sealed record CounterDecision(
    bool Allowed,
    int CurrentCount,
    int Limit,
    TimeSpan Window,
    TimeSpan? RetryAfter,
    string? ReasonCode,
    CounterStoreAvailability Availability = CounterStoreAvailability.Available,
    bool CooldownCreated = false)
{
    public bool Unavailable => Availability == CounterStoreAvailability.Unavailable || ReasonCode is AbuseReasonCodes.CounterStoreUnavailable or AbuseReasonCodes.CounterStoreTimeout;
    public bool CanAdmit => Allowed && !Unavailable;
}

public sealed record CooldownDecision(
    bool Active,
    TimeSpan? RetryAfter,
    string? ReasonCode,
    CounterStoreAvailability Availability = CounterStoreAvailability.Available)
{
    public bool Unavailable => Availability == CounterStoreAvailability.Unavailable || ReasonCode is AbuseReasonCodes.CounterStoreUnavailable or AbuseReasonCodes.CounterStoreTimeout;
    public bool BlocksAdmission => Active || Unavailable;
}

public sealed record AbusePolicyRequest(
    AbuseFeature Feature,
    Guid? AccountId = null,
    Guid? SessionId = null,
    Guid? ChallengeId = null,
    Guid? ResetId = null,
    SafeAbuseIdentifier? Identifier = null,
    SafeAbuseIdentifier? Ip = null,
    string? DeliveryMethod = null);

public sealed record AbuseEventRecord(
    AbuseFeature Feature,
    AbuseDecisionStatus Status,
    string? ReasonCode = null,
    Guid? AccountId = null,
    Guid? SessionId = null,
    Guid? ChallengeId = null,
    Guid? ResetId = null,
    SafeAbuseIdentifier? Identifier = null,
    SafeAbuseIdentifier? Ip = null,
    string? DeliveryMethod = null,
    TimeSpan? RetryAfter = null);
