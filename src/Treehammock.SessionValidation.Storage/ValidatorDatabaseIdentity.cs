using System.Data;
using NodaTime;
using Npgsql;
namespace Treehammock.SessionValidation.Storage;

// Owned by the future private host. Refresh at startup/background, never on a usable cache hit.
public sealed class ValidatorDatabaseIdentity : IAsyncDisposable
{
    internal NpgsqlDataSource Source { get; }
    private readonly IClock _clock;
    private readonly Func<CancellationToken,Task<string>> _inspect;
    private readonly Func<string,bool> _accept;
    private readonly SemaphoreSlim _audit = new(1,1);
    private readonly DatabaseIdentityAdmission _admission = new();
    internal ValidatorDatabaseIdentity(NpgsqlDataSource source, IClock clock)
        : this(source,clock,ct => YsqlIdentityAuditor.InspectAsync(source,ct)) { }
    internal ValidatorDatabaseIdentity(NpgsqlDataSource source, IClock clock, Func<CancellationToken,Task<string>> inspect, Func<string,bool>? accept = null)
    { Source = source; _clock = clock; _inspect = inspect; _accept = accept ?? DatabaseIdentityPolicy.Accept; }
    internal DatabaseIdentityAdmission Admission => _admission;
    public bool DatabaseFallbackReady => _admission.Capture(_clock.GetCurrentInstant()) != null;
    public async Task<DatabaseIdentityAuditResult> RefreshIdentityAsync(CancellationToken cancellationToken = default)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(3));
        bool acquired = false;
        Task<string>? pending = null;
        bool consumed = false;
        try
        {
            await _audit.WaitAsync(timeout.Token); acquired = true;
            if (_admission.Quarantined) return new(DatabaseIdentityAuditStatus.Quarantined);
            var before = _clock.GetCurrentInstant();
            pending = _inspect(timeout.Token);
            string json = await pending.WaitAsync(timeout.Token); consumed = true;
            cancellationToken.ThrowIfCancellationRequested();
            var after = _clock.GetCurrentInstant();
            if (timeout.IsCancellationRequested || after < before || after - before > Duration.FromSeconds(3))
            { _admission.Unavailable(); return new(DatabaseIdentityAuditStatus.Unavailable); }
            if (!_accept(json))
            { _admission.Reject(); return new(DatabaseIdentityAuditStatus.Rejected); }
            _admission.Verify(after); return new(DatabaseIdentityAuditStatus.Verified);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        { _admission.Unavailable(); throw; }
        catch (Exception) { _admission.Unavailable(); return new(DatabaseIdentityAuditStatus.Unavailable); }
        finally
        {
            // A timed-out provider still owns the single inspection slot until it settles.
            if (pending is not null && !consumed && acquired)
            {
                acquired = false;
                _ = pending.ContinueWith(t => { if (t.IsFaulted) _ = t.Exception; _audit.Release(); },CancellationToken.None,TaskContinuationOptions.ExecuteSynchronously,TaskScheduler.Default);
            }
            if (acquired) _audit.Release();
        }
    }
    internal async Task DrainAuditAsync(CancellationToken token) { await _audit.WaitAsync(token); _audit.Release(); }
    public async ValueTask DisposeAsync() { _admission.Reject(); await Source.DisposeAsync(); }
    public override string ToString() => nameof(ValidatorDatabaseIdentity);
}

internal sealed record IdentityAdmissionToken(Instant CheckedAt, Instant Until);
internal sealed class DatabaseIdentityAdmission
{
    private IdentityAdmissionToken? _current;
    private int _quarantined;
    internal bool Quarantined => Volatile.Read(ref _quarantined) != 0;
    internal IdentityAdmissionToken? Capture(Instant now)
    { var current=Volatile.Read(ref _current); return !Quarantined && current is not null && now>=current.CheckedAt && now<current.Until ? current : null; }
    internal bool IsCurrent(IdentityAdmissionToken token, Instant now) => ReferenceEquals(Capture(now), token);
    internal void Verify(Instant now)
    { if (!Quarantined) Volatile.Write(ref _current,new(now,now+Duration.FromSeconds(30))); }
    internal void Unavailable() => Volatile.Write(ref _current,null);
    internal void Reject() { Interlocked.Exchange(ref _quarantined,1); Unavailable(); }
}

internal static class YsqlIdentityAuditor
{
    internal static async Task<string> InspectAsync(NpgsqlDataSource source, CancellationToken cancellationToken)
    {
        await using var connection=await source.OpenConnectionAsync(cancellationToken);
        await using var transaction=await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead,cancellationToken);
        await using(var setup=new NpgsqlCommand("set transaction read only; set local search_path=pg_catalog; set local yb_read_from_followers=off; set local statement_timeout='2s'; set local lock_timeout='500ms'",connection,transaction))
        { setup.CommandTimeout=3; await setup.ExecuteNonQueryAsync(cancellationToken); }
        string json;
        await using(var command=new NpgsqlCommand(DatabaseIdentityPolicy.InspectionSql,connection,transaction))
        { command.CommandTimeout=3; json=(string)(await command.ExecuteScalarAsync(cancellationToken) ?? throw new InvalidOperationException("No identity result.")); }
        await transaction.CommitAsync(cancellationToken); return json;
    }
}
