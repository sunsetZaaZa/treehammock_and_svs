namespace treehammock.Rigging.Dependencies;

public enum DependencyFailureKind { Unavailable, InvalidResponse, CommitOutcomeUnknown }
public enum DependencyStage { Acquire, Begin, Execute, Read, Commit }
public sealed record DependencyFailure(string Dependency, string Operation, DependencyFailureKind Kind, DependencyStage Stage);

// Absence and rejected proofs stay normal domain results. Infrastructure failure cannot be mistaken for either.
public sealed class DependencyUnavailableException : Exception
{
    public DependencyFailure Failure { get; }
    public DependencyUnavailableException(DependencyFailure failure, Exception? inner = null)
        : base($"{failure.Dependency} is unavailable during {failure.Operation}.", inner) => Failure = failure;

    public static DependencyUnavailableException Database(string operation, DependencyStage stage, Exception? inner = null)
        => inner as DependencyUnavailableException ?? new(new("postgresql", operation,
            stage == DependencyStage.Commit ? DependencyFailureKind.CommitOutcomeUnknown : DependencyFailureKind.Unavailable, stage), inner);
    public static DependencyUnavailableException InvalidResponse(string operation)
        => new(new("postgresql", operation, DependencyFailureKind.InvalidResponse, DependencyStage.Read));
    public static DependencyUnavailableException Cache(string operation, Exception? inner = null)
        => new(new("dragonfly", operation, DependencyFailureKind.Unavailable, DependencyStage.Execute), inner);
}

public static class DependencyDeadline
{
    // Redis has no native command cancellation. A bounded wait abandons only the wait; always observe the command.
    public static async Task<T> RunAsync<T>(Func<CancellationToken, Task<T>> start, TimeSpan timeout, CancellationToken caller = default)
    {
        caller.ThrowIfCancellationRequested();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(caller);
        deadline.CancelAfter(timeout > TimeSpan.Zero ? timeout : TimeSpan.FromMilliseconds(1));
        Task<T> task = start(deadline.Token);
        try { return await task.WaitAsync(deadline.Token); }
        catch (OperationCanceledException) when (!caller.IsCancellationRequested)
        {
            Observe(task);
            throw new TimeoutException("Dependency deadline expired.");
        }
        catch (OperationCanceledException) { Observe(task); throw; }
    }
    public static void Observe(Task task) => _ = task.ContinueWith(t => { _ = t.Exception; },
        CancellationToken.None, TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
}
