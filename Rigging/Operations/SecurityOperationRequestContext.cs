using System.Security.Cryptography;
using treehammock.DataLayer.Operations;

namespace treehammock.Rigging.Operations;

public sealed class SecurityOperationRequestContext
{
    private static readonly AsyncLocal<SecurityOperationRequestContext?> Ambient = new();
    public static SecurityOperationRequestContext? Current => Ambient.Value;
    public string? ClientKey { get; init; }
    public string? RecoveryKey { get; init; }
    public required string Purpose { get; init; }
    public required byte[] CanonicalBody { get; init; }
    internal Guid? OperationId;
    internal byte[]? RecoveryBytes;
    internal bool Admitted;
    internal readonly SemaphoreSlim Admission = new(1, 1);
    private readonly Dictionary<string, int> _steps = new(StringComparer.Ordinal);
    internal string NextStep(string purpose)
    {
        lock (_steps) { _steps.TryGetValue(purpose, out int n); _steps[purpose] = n + 1; return $"{purpose}:{n}"; }
    }
    public static IDisposable Push(SecurityOperationRequestContext context)
    {
        var prior = Ambient.Value; Ambient.Value = context; return new Restore(prior);
    }
    private sealed class Restore(SecurityOperationRequestContext? prior) : IDisposable
    {
        public void Dispose() => Ambient.Value = prior;
    }
    public static SecurityOperationRequestContext Isolated(string purpose) => new()
    {
        ClientKey = SecurityOperationKey.Create(), RecoveryKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
        Purpose = purpose, CanonicalBody = []
    };
}
