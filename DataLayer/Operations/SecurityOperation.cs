using System.Globalization;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace treehammock.DataLayer.Operations;

[System.Text.Json.Serialization.JsonConverter(typeof(System.Text.Json.Serialization.JsonStringEnumConverter))]
public enum SecurityOperationState { Pending, Committed, RolledBack, PartiallyCommitted, Unknown, Expired }
public sealed record SecurityOperationStep(string Purpose, string Code, bool? Succeeded);
public sealed record SecurityOperationStatus(Guid OperationId, SecurityOperationState State,
    int? HttpStatus, IReadOnlyList<SecurityOperationStep> Steps);
public sealed record SecurityOperationKey(Guid Id, DateTimeOffset IssuedAt)
{
    public static string Create() => $"{DateTimeOffset.UtcNow.ToUnixTimeSeconds()}.{Guid.NewGuid():N}";
    public static SecurityOperationKey Parse(string value, int retentionSeconds)
    {
        string[] parts = value.Split('.');
        if (parts.Length != 2 || !long.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out long seconds)
            || !Guid.TryParseExact(parts[1], "N", out Guid id) || id == Guid.Empty)
            throw new SecurityOperationException("SECURITY_OPERATION_KEY_INVALID", 400);
        DateTimeOffset issued;
        try { issued = DateTimeOffset.FromUnixTimeSeconds(seconds); }
        catch (ArgumentOutOfRangeException) { throw new SecurityOperationException("SECURITY_OPERATION_KEY_INVALID", 400); }
        DateTimeOffset now = DateTimeOffset.UtcNow;
        if (issued > now.AddMinutes(2)) throw new SecurityOperationException("SECURITY_OPERATION_KEY_INVALID", 400);
        if (issued.AddSeconds(retentionSeconds) <= now)
            throw new SecurityOperationException("SECURITY_OPERATION_EXPIRED", 410);
        return new(id, issued);
    }
    public static byte[] ParseRecoveryKey(string value)
    {
        byte[] key;
        try { key = Convert.FromBase64String(value); }
        catch (FormatException) { throw new SecurityOperationException("SECURITY_OPERATION_RECOVERY_KEY_INVALID", 400); }
        if (key.Length != 32) throw new SecurityOperationException("SECURITY_OPERATION_RECOVERY_KEY_INVALID", 400);
        return key;
    }
}
public sealed class SecurityOperationException : Exception
{
    public string Code { get; }
    public int HttpStatus { get; }
    public SecurityOperationStatus? Status { get; }
    public SecurityOperationException(string code, int httpStatus, SecurityOperationStatus? status = null)
        : base(code) { Code = code; HttpStatus = httpStatus; Status = status; }
    public static SecurityOperationException Outcome(SecurityOperationStatus status) => new(
        "SECURITY_OPERATION_" + status.State.ToString().ToUpperInvariant(),
        status.State switch { SecurityOperationState.Pending => 202, SecurityOperationState.Unknown => 503,
            SecurityOperationState.Expired => 410, _ => 409 }, status);
}
// Receipt construction is an allowlist, not serialization of repository DTOs.
public sealed record SecurityOperationOutcome(string Code, bool? Succeeded)
{
    public static SecurityOperationOutcome From(object? value)
    {
        if (value is null) throw new InvalidOperationException("A mutation must return a controlled outcome before commit.");
        if (value is bool flag) return new(flag ? "SUCCEEDED" : "REJECTED", flag);
        if (value is Enum enumeration) return new(SafeCode(enumeration.ToString()), null);
        if (value is System.Runtime.CompilerServices.ITuple tuple && tuple.Length > 1 && tuple[1] is Enum code)
            return new(SafeCode(code.ToString()), null);
        var type = value.GetType();
        object? result = type.GetProperty("Result")?.GetValue(value) ?? type.GetProperty("Succeeded")?.GetValue(value);
        object? domainCode = type.GetProperty("Code")?.GetValue(value) ?? type.GetProperty("Status")?.GetValue(value);
        if (domainCode is not string && domainCode is not Enum)
            throw new InvalidOperationException("Mutation outcome has no allowlisted code.");
        return new(SafeCode(domainCode.ToString()!), result is bool success ? success : null);
    }
    private static string SafeCode(string value)
    {
        string code = value.ToUpperInvariant();
        if (!Regex.IsMatch(code, "^[A-Z0-9_]{1,96}$", RegexOptions.CultureInvariant))
            throw new InvalidOperationException("Invalid safe operation outcome code.");
        return code;
    }
}
