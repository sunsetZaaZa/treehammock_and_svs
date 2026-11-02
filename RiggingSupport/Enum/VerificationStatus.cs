namespace treehammock.RiggingSupport.Enum;

public enum VerificationStatus
{
    STARTED = 0,
    SUCCESSFUL = 1,
    SENT = 2,
    EXPIRED = 3,
    REFRESHED = 4,
    FAILED = 5,
    REPLACED = 6
}

public enum VerificationResendStatus
{
    VERIFEID = 1,
    UNVERIFIED = 2,
    NETWORKVERIFIED = 3,
    AUTHENTICATEDVERIFIED = 4,
    NONE = 5
}
