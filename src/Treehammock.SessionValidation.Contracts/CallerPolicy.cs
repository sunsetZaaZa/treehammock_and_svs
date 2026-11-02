namespace Treehammock.SessionValidation.Contracts;

// Caller admission is separate from user/action permission adjudication in the later evaluator.
// There is deliberately no built-in production caller or wildcard grant.
public sealed class CallerPolicy
{
    private readonly Dictionary<string, HashSet<string>> _callers = new(StringComparer.Ordinal);
    public static CallerPolicy DenyAll { get; } = new(Array.Empty<KeyValuePair<string, string[]>>());

    public CallerPolicy(IEnumerable<KeyValuePair<string, string[]>> callers)
    {
        foreach (var (identity, actions) in callers)
        {
            if (!IsCanonicalIdentity(identity) || actions is null || actions.Length == 0 || actions.Any(a => !IsSupportedAction(a)))
                throw new ArgumentException("Invalid caller policy entry.");
            if (!_callers.TryAdd(identity, new HashSet<string>(actions, StringComparer.Ordinal)))
                throw new ArgumentException("Duplicate caller policy identity.");
        }
    }

    public bool Allows(string? authenticatedPeerIdentity, string action) =>
        authenticatedPeerIdentity is not null && _callers.TryGetValue(authenticatedPeerIdentity, out var actions) && actions.Contains(action);

    public static bool IsSupportedAction(string? action) => action is
        "backup.read" or "backup.write" or "recovery_package.read" or "recovery_package.write";

    private static bool IsCanonicalIdentity(string? value)
    {
        if (value is not { Length: >= 1 and <= 256 } || value.Any(c => c < 33 || c > 126) ||
            !Uri.TryCreate(value, UriKind.Absolute, out var uri)) return false;
        const string prefix = "/service/";
        var service = uri.AbsolutePath.StartsWith(prefix, StringComparison.Ordinal) ? uri.AbsolutePath[prefix.Length..] : "";
        return service.Length is >= 1 and <= 64 && service[0] is >= 'a' and <= 'z' &&
               service.All(c => c is >= 'a' and <= 'z' or >= '0' and <= '9' or '-') &&
               uri.Scheme == "spiffe" && !string.IsNullOrEmpty(uri.Host) && uri.UserInfo.Length == 0 &&
               uri.Query.Length == 0 && uri.Fragment.Length == 0 && uri.Port == -1 &&
               uri.AbsolutePath.StartsWith("/service/", StringComparison.Ordinal) &&
               value == uri.AbsoluteUri && !value.Contains('%') && !value.Contains("//service/", StringComparison.Ordinal);
    }
}
