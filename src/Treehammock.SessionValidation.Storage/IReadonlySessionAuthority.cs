using NodaTime;
namespace Treehammock.SessionValidation.Storage;

// In-process only: hash is server-derived, never a caller-supplied account assertion.
public interface IReadonlySessionAuthority
{
    Task<AuthorityReadResult> ReadAsync(string accessTokenHash, Instant deadline, CancellationToken cancellationToken = default);
}
public enum AuthorityReadStatus { Unspecified, Found, NotFound, Unauthenticated, Unavailable }
public sealed class AuthorityReadResult : IDisposable
{
    internal AuthorityReadResult(AuthorityReadStatus status, AuthSessionProjection? projection = null)
    { Status = status; Projection = projection; }
    public AuthorityReadStatus Status { get; }
    public AuthSessionProjection? Projection { get; }
    public void Dispose() => Projection?.Dispose();
    public override string ToString() => $"AuthorityReadResult({Status})";
}
