namespace treehammock.RiggingSupport.Enum;

/// <summary>
/// Provider protocol names retained for entity compile compatibility.
/// </summary>
public enum Protocol_PeerToPeer
{
    NONE = 0,
    HTTP = 1,
    HTTPS = 2,
    SMTP = 3,
    SMS = 4,
    OAUTH = 5,
    AUTHENTICATOR_APP = 6
}

/// <summary>
/// Provider enum retained for authentication-provider token entities.
/// </summary>
public enum TwoFactorAuthProvider
{
    NONE = 0,
    EMAIL = 1,
    SMS = 2,
    AUTHENTICATOR_APP = 3,
    GOOGLE = 4,
    OAUTH = 5
}
