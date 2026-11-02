namespace treehammock.RiggingSupport.Enum;

public enum PasswordResetSessionState
{
    ResetTokenIssued = 1,
    ResetTokenVerified = 2,
    TwoFactorSelectionRequired = 3,
    AwaitingSmsCode = 4,
    AwaitingEmailCode = 5,
    AwaitingAuthenticatorCode = 6,
    TwoFactorComplete = 7,
    PasswordChanged = 8,
    Expired = 9,
    Failed = 10
}
