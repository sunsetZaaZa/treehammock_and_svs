namespace treehammock.Rigging.Abuse;

public static class AbuseReasonCodes
{
    public const string TwoFactorAttemptsExceeded = "ABUSE_TWO_FACTOR_ATTEMPTS_EXCEEDED";
    public const string TwoFactorSetupAttemptsExceeded = "ABUSE_TWO_FACTOR_SETUP_ATTEMPTS_EXCEEDED";
    public const string DeliveryThrottleExceeded = "ABUSE_DELIVERY_THROTTLE_EXCEEDED";
    public const string FailureCooldownActive = "ABUSE_FAILURE_COOLDOWN_ACTIVE";
    public const string LoginThrottleExceeded = "ABUSE_LOGIN_THROTTLE_EXCEEDED";
    public const string PasswordResetRequestThrottleExceeded = "ABUSE_PASSWORD_RESET_REQUEST_THROTTLE_EXCEEDED";
    public const string PasswordResetTokenVerificationThrottleExceeded = "ABUSE_PASSWORD_RESET_TOKEN_VERIFICATION_THROTTLE_EXCEEDED";
    public const string PasswordResetTwoFactorProofThrottleExceeded = "ABUSE_PASSWORD_RESET_TWO_FACTOR_PROOF_THROTTLE_EXCEEDED";
    public const string PasswordResetFinalizeThrottleExceeded = "ABUSE_PASSWORD_RESET_FINALIZE_THROTTLE_EXCEEDED";
    public const string AccountUnlockVerifyAttemptsExceeded = "ABUSE_ACCOUNT_UNLOCK_VERIFY_ATTEMPTS_EXCEEDED";
    public const string AccountDeleteFinalizeAttemptsExceeded = "ABUSE_ACCOUNT_DELETE_FINALIZE_ATTEMPTS_EXCEEDED";
    public const string PublicTokenVerificationAttemptsExceeded = "ABUSE_PUBLIC_TOKEN_VERIFICATION_ATTEMPTS_EXCEEDED";
    public const string ActivationVerifyAttemptsExceeded = "ABUSE_ACTIVATION_VERIFY_ATTEMPTS_EXCEEDED";
    public const string CounterStoreUnavailable = "ABUSE_COUNTER_STORE_UNAVAILABLE";
    public const string CounterStoreTimeout = "ABUSE_COUNTER_STORE_TIMEOUT";
    public const string CounterLimitExceeded = "ABUSE_COUNTER_LIMIT_EXCEEDED";
}
