using System.Diagnostics.Metrics;

using treehammock.Rigging.Abuse;

namespace treehammock.Rigging.Observability;

public static class AbuseOperationalEventNames
{
    public const string PolicyAllowed = "abuse.policy_allowed";
    public const string PolicyDenied = "abuse.policy_denied";
    public const string CooldownStarted = "abuse.cooldown_started";
    public const string CounterStoreTimeout = "abuse.counter_store_timeout";
    public const string CounterStoreFailed = "abuse.counter_store_failed";
    public const string DeliveryThrottled = "delivery.throttled";
    public const string LoginThrottled = "login.throttled";
    public const string PasswordResetThrottled = "password_reset.throttled";
    public const string TwoFactorThrottled = "two_factor.throttled";
    public const string CloudflareChallengeDetected = "cloudflare.challenge_detected";
    public const string CloudflareBotSignalHigh = "cloudflare.bot_signal_high";
    public const string OriginBypassDenied = "edge.origin_bypass_denied";
}

public static class AbuseMetricNames
{
    public const string CounterAdmissionsTotal = "treehammock_abuse_counter_admissions_v2_total";
    public const string CooldownsStartedTotal = "treehammock_abuse_cooldowns_created_v2_total";
    public const string CooldownBlockedAttemptsTotal = "treehammock_abuse_cooldown_blocked_attempts_total";
    public const string CounterStoreFailuresTotal = "treehammock_abuse_counter_store_failures_total";
    public const string DeliveryThrottledTotal = "treehammock_delivery_throttled_total";
    public const string LoginThrottledTotal = "treehammock_login_throttled_total";
    public const string PasswordResetThrottledTotal = "treehammock_password_reset_throttled_total";
    public const string TwoFactorThrottledTotal = "treehammock_two_factor_throttled_total";
    public const string EdgeAbuseEventsTotal = "treehammock_edge_abuse_events_total";
}

public static class AbuseMetricLabels
{
    public const string Event = "event";
    public const string Feature = "feature";
    public const string Dimension = "dimension";
    public const string Outcome = "outcome";
    public const string Reason = "reason";
    public const string DeliveryMethod = "delivery_method";
    public const string Operation = "operation";
    public const string Dependency = "dependency";

    public static readonly IReadOnlySet<string> Allowed = new HashSet<string>(StringComparer.Ordinal)
    {
        Event,
        Feature,
        Dimension,
        Outcome,
        Reason,
        DeliveryMethod,
        Operation,
        Dependency
    };

    public static readonly IReadOnlySet<string> Forbidden = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "account_id",
        "accountId",
        "session_id",
        "sessionId",
        "challenge_id",
        "challengeId",
        "reset_id",
        "resetId",
        "emailAddress",
        "email",
        "phoneNumber",
        "phone",
        "username",
        "identifier",
        "token",
        "sensitiveActionToken",
        "setupId",
        "manualEntryKey",
        "otpauthUri",
        "accessToken",
        "refreshToken",
        "resetCode",
        "totpCode",
        "totpSecret",
        "password",
        "passwordHash",
        "ip",
        "ipAddress",
        "clientIp",
        "connectionString"
    };
}

public static class AbuseOperationalTelemetry
{
    public const string MeterName = "treehammock.abuse";
    public const string MeterVersion = "2.0.0";
    public const string DependencyDragonfly = "dragonfly";

    private static readonly Meter Meter = new(MeterName, MeterVersion);

    private static readonly Counter<long> PolicyDecisions = Meter.CreateCounter<long>(
        AbuseMetricNames.CounterAdmissionsTotal,
        unit: "decisions",
        description: "One terminal outcome per completed counter IncrementAsync call; not HTTP requests.");

    private static readonly Counter<long> CooldownsStarted = Meter.CreateCounter<long>(
        AbuseMetricNames.CooldownsStartedTotal,
        unit: "cooldowns",
        description: "Confirmed atomic cooldown creation by backend; repeated denial is not creation.");

    private static readonly Counter<long> CounterStoreFailures = Meter.CreateCounter<long>(
        AbuseMetricNames.CounterStoreFailuresTotal,
        unit: "failures",
        description: "Backend abuse counter operation failures and timeouts by bounded dependency, operation and reason.");

    private static readonly Counter<long> DeliveryThrottled = Meter.CreateCounter<long>(
        AbuseMetricNames.DeliveryThrottledTotal,
        unit: "throttles",
        description: "Email/SMS delivery throttles by delivery method and reason.");

    private static readonly Counter<long> LoginThrottled = Meter.CreateCounter<long>(
        AbuseMetricNames.LoginThrottledTotal,
        unit: "throttles",
        description: "Login abuse throttles by bounded dimension and reason.");

    private static readonly Counter<long> PasswordResetThrottled = Meter.CreateCounter<long>(
        AbuseMetricNames.PasswordResetThrottledTotal,
        unit: "throttles",
        description: "Password-reset request/finalize throttles by bounded feature, dimension, and reason.");

    private static readonly Counter<long> TwoFactorThrottled = Meter.CreateCounter<long>(
        AbuseMetricNames.TwoFactorThrottledTotal,
        unit: "throttles",
        description: "Two-factor challenge throttles by bounded dimension and reason.");

    private static readonly Counter<long> EdgeAbuseEvents = Meter.CreateCounter<long>(
        AbuseMetricNames.EdgeAbuseEventsTotal,
        unit: "events",
        description: "Cloudflare/edge abuse-control observations by bounded event and outcome.");

    private static readonly Counter<long> CooldownBlockedAttempts = Meter.CreateCounter<long>(
        AbuseMetricNames.CooldownBlockedAttemptsTotal, unit: "attempts",
        description: "Counter admissions denied by an existing cooldown; excludes lookups and newly created cooldowns.");

    // Sole owner: DragonflyAbuseCounterStore's public admission boundary, after durable/cache resolution.
    public static void RecordCounterAdmission(AbuseFeature feature, AbuseCounterDimension dimension, CounterDecision decision)
    {
        PolicyDecisions.Add(1,
            Tag(AbuseMetricLabels.Feature, FeatureName(feature)),
            Tag(AbuseMetricLabels.Dimension, DimensionName(dimension)),
            Tag(AbuseMetricLabels.Outcome, decision.CanAdmit ? "allowed" : "denied"),
            Tag(AbuseMetricLabels.Reason, ReasonName(decision.ReasonCode)));
        if (!decision.CanAdmit && !decision.Unavailable && decision.ReasonCode == AbuseReasonCodes.FailureCooldownActive)
            CooldownBlockedAttempts.Add(1,
                Tag(AbuseMetricLabels.Feature, FeatureName(feature)),
                Tag(AbuseMetricLabels.Dimension, DimensionName(dimension)));
    }

    public static void RecordCounterStoreFailure(string operation, string? reasonCode, string dependency = DependencyDragonfly)
    {
        CounterStoreFailures.Add(
            1,
            Tag(AbuseMetricLabels.Dependency, DependencyName(dependency)),
            Tag(AbuseMetricLabels.Operation, OperationName(operation)),
            Tag(AbuseMetricLabels.Reason, ReasonName(reasonCode)));
    }

    public static void RecordCooldownStarted(
        AbuseFeature feature,
        AbuseCounterDimension dimension,
        string? reasonCode, string dependency)
    {
        CooldownsStarted.Add(
            1,
            Tag(AbuseMetricLabels.Dependency, DependencyName(dependency)),
            Tag(AbuseMetricLabels.Feature, FeatureName(feature)),
            Tag(AbuseMetricLabels.Dimension, DimensionName(dimension)),
            Tag(AbuseMetricLabels.Reason, ReasonName(reasonCode)));
    }

    public static void RecordDeliveryThrottled(string method, string? reasonCode)
    {
        DeliveryThrottled.Add(
            1,
            Tag(AbuseMetricLabels.DeliveryMethod, NormalizeDeliveryMethod(method)),
            Tag(AbuseMetricLabels.Reason, ReasonName(reasonCode)));
    }

    public static void RecordLoginThrottled(AbuseCounterDimension dimension, string? reasonCode)
    {
        LoginThrottled.Add(
            1,
            Tag(AbuseMetricLabels.Dimension, DimensionName(dimension)),
            Tag(AbuseMetricLabels.Reason, ReasonName(reasonCode)));
    }

    public static void RecordPasswordResetThrottled(
        AbuseFeature feature,
        AbuseCounterDimension dimension,
        string? reasonCode)
    {
        PasswordResetThrottled.Add(
            1,
            Tag(AbuseMetricLabels.Feature, FeatureName(feature)),
            Tag(AbuseMetricLabels.Dimension, DimensionName(dimension)),
            Tag(AbuseMetricLabels.Reason, ReasonName(reasonCode)));
    }

    public static void RecordTwoFactorThrottled(AbuseCounterDimension dimension, string? reasonCode)
    {
        TwoFactorThrottled.Add(
            1,
            Tag(AbuseMetricLabels.Dimension, DimensionName(dimension)),
            Tag(AbuseMetricLabels.Reason, ReasonName(reasonCode)));
    }

    public static void RecordEdgeAbuseEvent(string eventName, string outcome)
    {
        EdgeAbuseEvents.Add(
            1,
            Tag(AbuseMetricLabels.Event, EventName(eventName)),
            Tag(AbuseMetricLabels.Outcome, OutcomeName(outcome)));
    }

    private static KeyValuePair<string, object?> Tag(string name, string value)
    {
        if (!AbuseMetricLabels.Allowed.Contains(name) || AbuseMetricLabels.Forbidden.Contains(name))
        {
            throw new ArgumentException("Abuse metric tag name is not allowed.", nameof(name));
        }

        return new KeyValuePair<string, object?>(name, value);
    }

    private static string FeatureName(AbuseFeature feature) => Enum.IsDefined(feature) ? feature.ToString().ToLowerInvariant() : "unknown";
    private static string DimensionName(AbuseCounterDimension dimension) => Enum.IsDefined(dimension) ? dimension.ToString().ToLowerInvariant() : "unknown";
    private static string ReasonName(string? reasonCode) => reasonCode switch
    {
        AbuseReasonCodes.TwoFactorAttemptsExceeded => "abuse_two_factor_attempts_exceeded",
        AbuseReasonCodes.TwoFactorSetupAttemptsExceeded => "abuse_two_factor_setup_attempts_exceeded",
        AbuseReasonCodes.DeliveryThrottleExceeded => "abuse_delivery_throttle_exceeded",
        AbuseReasonCodes.FailureCooldownActive => "abuse_failure_cooldown_active",
        AbuseReasonCodes.LoginThrottleExceeded => "abuse_login_throttle_exceeded",
        AbuseReasonCodes.PasswordResetRequestThrottleExceeded => "abuse_password_reset_request_throttle_exceeded",
        AbuseReasonCodes.PasswordResetTokenVerificationThrottleExceeded => "abuse_password_reset_token_verification_throttle_exceeded",
        AbuseReasonCodes.PasswordResetTwoFactorProofThrottleExceeded => "abuse_password_reset_two_factor_proof_throttle_exceeded",
        AbuseReasonCodes.PasswordResetFinalizeThrottleExceeded => "abuse_password_reset_finalize_throttle_exceeded",
        AbuseReasonCodes.AccountUnlockVerifyAttemptsExceeded => "abuse_account_unlock_verify_attempts_exceeded",
        AbuseReasonCodes.AccountDeleteFinalizeAttemptsExceeded => "abuse_account_delete_finalize_attempts_exceeded",
        AbuseReasonCodes.PublicTokenVerificationAttemptsExceeded => "abuse_public_token_verification_attempts_exceeded",
        AbuseReasonCodes.ActivationVerifyAttemptsExceeded => "abuse_activation_verify_attempts_exceeded",
        AbuseReasonCodes.CounterStoreUnavailable => "abuse_counter_store_unavailable",
        AbuseReasonCodes.CounterStoreTimeout => "abuse_counter_store_timeout",
        AbuseReasonCodes.CounterLimitExceeded => "abuse_counter_limit_exceeded",
        null or "" => "none",
        _ => "unknown"
    };
    private static string NormalizeDeliveryMethod(string? method) => method?.Trim().ToLowerInvariant() switch
    { "sms" or "phone" or "sms_key" => "sms", "email" => "email", _ => "unknown" };
    private static string DependencyName(string? dependency) => dependency switch
    { "dragonfly" or "postgresql" => dependency, _ => "unknown" };
    private static string OperationName(string? operation) => operation switch
    { "increment" or "reset" or "cooldown_lookup" or "budget_cleanup" => operation, _ => "unknown" };
    private static string EventName(string? name) => name switch
    {
        AbuseOperationalEventNames.CloudflareChallengeDetected => AbuseOperationalEventNames.CloudflareChallengeDetected,
        AbuseOperationalEventNames.CloudflareBotSignalHigh => AbuseOperationalEventNames.CloudflareBotSignalHigh,
        AbuseOperationalEventNames.OriginBypassDenied => AbuseOperationalEventNames.OriginBypassDenied,
        _ => "unknown"
    };
    private static string OutcomeName(string? outcome) => outcome switch
    { "allowed" or "denied" or "detected" or "high" => outcome, _ => "unknown" };
}
