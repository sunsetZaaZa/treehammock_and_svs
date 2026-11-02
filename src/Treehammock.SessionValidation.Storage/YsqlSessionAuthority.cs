using NodaTime;
using Npgsql;
namespace Treehammock.SessionValidation.Storage;

public sealed class YsqlSessionAuthority : IReadonlySessionAuthority
{
    private readonly IYsqlSnapshotExecutor _executor;
    private readonly IClock _clock;
    private readonly TimeSpan _budget;
    private readonly DatabaseIdentityAdmission? _admission;
    private readonly Func<IDisposable>? _ownOperation;
    public YsqlSessionAuthority(ValidatorDatabaseIdentity identity, TimeSpan readBudget, IClock? clock = null, Func<IDisposable>? ownOperation = null)
        : this(new NpgsqlSnapshotExecutor(identity.Source), readBudget, clock ?? SystemClock.Instance, identity.Admission, ownOperation) { }
    internal YsqlSessionAuthority(IYsqlSnapshotExecutor executor, TimeSpan readBudget, IClock clock, DatabaseIdentityAdmission? admission = null, Func<IDisposable>? ownOperation = null)
    {
        if (readBudget < TimeSpan.FromMilliseconds(1) || readBudget > TimeSpan.FromSeconds(30))
            throw new ArgumentOutOfRangeException(nameof(readBudget));
        _executor = executor; _clock = clock; _budget = readBudget; _admission = admission; _ownOperation = ownOperation;
    }
    public async Task<AuthorityReadResult> ReadAsync(string accessTokenHash, Instant deadline, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var now = _clock.GetCurrentInstant();
        var admission = _admission?.Capture(now);
        if (_admission is not null && admission is null) return new(AuthorityReadStatus.Unavailable);
        if (deadline <= now || !IsHash(accessTokenHash)) return new(AuthorityReadStatus.Unavailable);
        var remaining = (deadline - now).ToTimeSpan();
        var budget = remaining < _budget ? remaining : _budget;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(budget);
        Task<CurrentSessionRow?>? pending = null;
        bool consumed = false;
        IDisposable? operation = null;
        try
        {
            operation = _ownOperation?.Invoke();
            pending = _executor.ReadAsync(accessTokenHash, budget, timeout.Token);
            using var row = await pending.WaitAsync(timeout.Token);
            consumed = true;
            var after = _clock.GetCurrentInstant();
            cancellationToken.ThrowIfCancellationRequested();
            if (timeout.IsCancellationRequested || after >= deadline || after < now ||
                (_admission is not null && !_admission.IsCurrent(admission!,after))) return new(AuthorityReadStatus.Unavailable);
            return row is null ? new(AuthorityReadStatus.NotFound) : AuthorityProjectionMapper.Map(row, accessTokenHash, after);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception) { return new(AuthorityReadStatus.Unavailable); }
        finally
        {
            // An uncooperative driver/double may finish after WaitAsync timed out. Observe and erase it.
            if (pending is not null && !consumed)
            {
                var lateOwner=operation;operation=null;
                _ = pending.ContinueWith(t => { try { if (t.IsCompletedSuccessfully) t.Result?.Dispose(); else _ = t.Exception; } finally { lateOwner?.Dispose(); } },
                    CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            }
            operation?.Dispose();
        }
    }
    internal static bool IsHash(string? value) => value is { Length: 64 } && value.All(c => c is >= '0' and <= '9' or >= 'A' and <= 'F');
}
internal interface IYsqlSnapshotExecutor
{
    Task<CurrentSessionRow?> ReadAsync(string binding, TimeSpan budget, CancellationToken cancellationToken);
}
