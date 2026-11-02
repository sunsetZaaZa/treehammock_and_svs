namespace treehammock.Rigging.Security;

/// <summary>
/// Canonical byte sizes and storage contracts for account cryptographic material.
/// Keep service generation, repository mapping, database procedures, and tests aligned here.
/// </summary>
public static class AccountCryptoSizes
{
    public const int PasswordHashBytes = 128;
    public const int WebKeyBytes = 128;
    public const int SaltOneBytes = 64;
    public const int SivBytes = 32;
    public const int NonceBytes = 16;

    public const int WebKeyBase64UrlLength = 171;

    public const string HashedPasswordStorage = "bytea";
    public const string WebKeyStorage = "text/base64url";
    public const string SaltOneStorage = "bytea";
    public const string SivStorage = "bytea";
    public const string NonceStorage = "bytea";
    public const string RefreshTokenStorage = "bytea";
    public const string AccessTokenHashStorage = "text/sha256-hex";
}
