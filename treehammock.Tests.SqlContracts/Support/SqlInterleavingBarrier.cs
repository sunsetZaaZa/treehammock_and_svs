using Npgsql;

namespace treehammock.Tests.SqlContracts.Support;

internal sealed record SqlLockObservation(int ContenderPid, int BlockerPid, string WaitEvent, string TransactionId);

/// <summary>Observe an actual backend lock relationship before explicitly releasing its blocker.</summary>
internal static class SqlInterleavingBarrier
{
    public static async Task<SqlLockObservation> WaitForBlockedAsync(NpgsqlConnection observer, int contenderPid,
        int blockerPid, Task contender, CancellationToken cancellation, TimeSpan? timeout = null)
    {
        if (contenderPid == blockerPid) throw new ArgumentException("Barrier requires independent backends.");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        deadline.CancelAfter(timeout ?? TimeSpan.FromSeconds(10));
        try
        {
            while (true)
            {
                deadline.Token.ThrowIfCancellationRequested();
                if (contender.IsCompleted)
                {
                    await contender; // Preserve a real command failure instead of claiming a blocked schedule.
                    throw new InvalidOperationException("Contender completed before the expected lock was observed.");
                }
                await using var command = new NpgsqlCommand("""
                    select wait_event, coalesce(backend_xid::text, '')
                    from pg_stat_activity
                    where pid = @contender and wait_event_type = 'Lock'
                      and @blocker = any(pg_blocking_pids(pid));
                    """, observer) { CommandTimeout = 5 };
                command.Parameters.AddWithValue("contender", contenderPid);
                command.Parameters.AddWithValue("blocker", blockerPid);
                await using (var reader = await command.ExecuteReaderAsync(deadline.Token))
                {
                    if (await reader.ReadAsync(deadline.Token))
                        return new SqlLockObservation(contenderPid, blockerPid, reader.GetString(0), reader.GetString(1));
                }
                // Delay only yields while inspecting live state; elapsed time never establishes success.
                await Task.Delay(TimeSpan.FromMilliseconds(20), deadline.Token);
            }
        }
        catch (OperationCanceledException) when (!cancellation.IsCancellationRequested)
        {
            throw new TimeoutException("The exact contender/blocker lock relationship was not observed within the barrier budget.");
        }
    }
}
