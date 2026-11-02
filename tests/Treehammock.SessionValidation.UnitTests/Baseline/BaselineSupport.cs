namespace Svs02.FrozenBaseline;

// Compile-only stand-ins for unchanged original utility configuration/logging. The frozen
// validation method and token generation body are copied byte-for-byte from v1.1.
public interface IOptions<out T> { T Value { get; } }
public sealed record Options<T>(T Value) : IOptions<T>;
public sealed class JWTSettings { public string JsonWebTokenIssuer { get; init; } = "svs02.test"; }
public interface ILogger
{
    void LogInformation(string message, params object?[] args);
    void LogWarning(string message, params object?[] args);
}
public interface ILogger<T> : ILogger;
public sealed class RecordingLogger<T> : ILogger<T>
{
    public string? Reason { get; private set; }
    public string? ExceptionType { get; private set; }
    public void LogInformation(string message, params object?[] args) => Record(args);
    public void LogWarning(string message, params object?[] args) => Record(args);
    private void Record(object?[] args)
    {
        Reason = args.Length > 0 ? args[0]?.ToString() : null;
        ExceptionType = args.Length > 1 ? args[1]?.ToString() : null;
    }
}
public enum IntraMessage
{
    TOKEN_THREW_EXCEPTION_IN_VALIDATION = 1000, TOKEN_FAILED_VALIDATION = 1010,
    TOKEN_PASSED_VALIDATION = 1020, TOKEN_AT_EXPIRATION = 1040,
    TOKEN_EXPIRED_VALIDATION = 1070, TOKEN_VALIDATION_MALFORMED = 1090
}
public static class JsonWebTokenPurpose
{
    public const string ClaimType = "purpose", WebKeyClaimType = "webKey", Active = "active_v2", PreAuthTwoFactor = "preauth_2fa";
}
