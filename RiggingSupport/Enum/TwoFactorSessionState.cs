namespace treehammock.RiggingSupport.Enum;

public enum TwoFactorSessionState
{
    SelectionRequired = 1,
    AwaitingSmsCode = 2,
    AwaitingEmailCode = 3,
    AwaitingAuthenticatorCode = 4,
    Complete = 5,
    Expired = 6,
    Failed = 7
}
