namespace treehammock.RiggingSupport.Enum;

/// <summary>
/// Account unlock token status names used by the lockout recovery flow.
/// </summary>
public enum AccountRecovery_Status
{
    NONE = 0,
    STARTED = 1,
    STANDBY = 2,
    RESENT = 3,
    CANCELED = 4,
    EXPIRED = 5,
    MID_RESEND = 6,
    COMPLETE = 7,
    BAD_TOKEN = 9,
    BAD_METHOD = 10,
    BAD_VERIFY = 11,
    BAD_TOPIC = 12,
    NOT_LOCKED = 13,
    STALE_LOCKOUT = 14
}

