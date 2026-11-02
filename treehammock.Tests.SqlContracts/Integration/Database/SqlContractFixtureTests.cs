using Npgsql;
using Shouldly;
using treehammock.Tests.SqlContracts.Support;

namespace treehammock.Tests.Integration.Database;

[Trait("Suite", "SqlContracts")]
public sealed class SqlContractFixtureTests
{
    [Fact]
    public async Task Independent_runs_own_distinct_schemas_and_teardown_preserves_the_other_run()
    {
        Task<SqlContractFixture>[] starts = [
            SqlContractFixture.CreateAsync(TestContext.Current.CancellationToken, installBaseline: false),
            SqlContractFixture.CreateAsync(TestContext.Current.CancellationToken, installBaseline: false)];
        SqlContractFixture[] fixtures;
        try { fixtures = await Task.WhenAll(starts); }
        catch
        {
            foreach (var start in starts.Where(start => start.IsCompletedSuccessfully)) await start.Result.DisposeAsync();
            throw;
        }
        try
        {
            fixtures[0].Schema.ShouldNotBe(fixtures[1].Schema);
            var other = await fixtures[1].OpenConnectionAsync();
            await fixtures[1].ExecuteAsync(other, "create table owned_probe(value int); insert into owned_probe values(42);");
            await fixtures[0].DisposeAsync();
            (await ScalarAsync<long>(other, "select count(*) from owned_probe;", fixtures[1].Token)).ShouldBe(1);
            (await ScalarAsync<bool>(other, $"select exists(select 1 from pg_namespace where nspname = '{fixtures[0].Schema}');", fixtures[1].Token)).ShouldBeFalse();
        }
        finally
        {
            foreach (var fixture in fixtures) await fixture.DisposeAsync();
        }
    }

    [Fact]
    public async Task Barrier_observes_the_exact_blocker_and_releases_the_contender_after_commit()
    {
        await SqlContractFixture.RunAsync(async (fixture, cancellation) =>
        {
            var observer = await fixture.OpenConnectionAsync();
            var blocker = await fixture.OpenConnectionAsync();
            var contender = await fixture.OpenConnectionAsync();
            await fixture.ExecuteAsync(observer, "create table lock_probe(id int primary key, value int); insert into lock_probe values(1, 0);");
            var first = await fixture.BeginTransactionAsync(blocker);
            await fixture.ExecuteAsync(blocker, "update lock_probe set value = 1 where id = 1;", first);
            var second = await fixture.BeginTransactionAsync(contender);
            Task work = fixture.Observe(fixture.ExecuteAsync(contender, "update lock_probe set value = 2 where id = 1;", second));
            SqlLockObservation observed = await SqlInterleavingBarrier.WaitForBlockedAsync(observer, contender.ProcessID, blocker.ProcessID, work, cancellation);
            observed.BlockerPid.ShouldBe(blocker.ProcessID);
            observed.ContenderPid.ShouldBe(contender.ProcessID);
            observed.TransactionId.ShouldNotBeNullOrWhiteSpace();
            await first.CommitAsync(cancellation);
            await work.WaitAsync(cancellation);
            await second.CommitAsync(cancellation);
            (await ScalarAsync<int>(observer, "select value from lock_probe where id = 1;", cancellation)).ShouldBe(2);
        }, TestContext.Current.CancellationToken, installBaseline: false);
    }

    [Fact]
    public async Task Wrong_blocker_times_out_and_teardown_cancels_and_observes_all_owned_work()
    {
        var fixture = await SqlContractFixture.CreateAsync(TestContext.Current.CancellationToken, installBaseline: false);
        Task? work = null;
        try
        {
            var observer = await fixture.OpenConnectionAsync();
            var blocker = await fixture.OpenConnectionAsync();
            var contender = await fixture.OpenConnectionAsync();
            await fixture.ExecuteAsync(observer, "create table lock_probe(id int primary key); insert into lock_probe values(1);");
            var transaction = await fixture.BeginTransactionAsync(blocker);
            await fixture.ExecuteAsync(blocker, "update lock_probe set id = 1;", transaction);
            work = fixture.Observe(fixture.ExecuteAsync(contender, "update lock_probe set id = 1;"));
            await Should.ThrowAsync<TimeoutException>(() => SqlInterleavingBarrier.WaitForBlockedAsync(
                observer, contender.ProcessID, observer.ProcessID, work, fixture.Token, TimeSpan.FromMilliseconds(150)));
            fixture.ObservedTasks.ShouldBe(1);
        }
        finally { await fixture.DisposeAsync(); }
        work.ShouldNotBeNull();
        work.IsCompleted.ShouldBeTrue();
        fixture.Connections.All(c => c.State == System.Data.ConnectionState.Closed).ShouldBeTrue();
    }

    [Fact]
    public async Task Caller_cancellation_is_preserved_instead_of_reclassified_as_barrier_timeout()
    {
        await SqlContractFixture.RunAsync(async (fixture, cancellation) =>
        {
            var observer = await fixture.OpenConnectionAsync();
            using var caller = new CancellationTokenSource();
            caller.Cancel();
            await Should.ThrowAsync<OperationCanceledException>(() => SqlInterleavingBarrier.WaitForBlockedAsync(
                observer, observer.ProcessID + 1, observer.ProcessID, new TaskCompletionSource<bool>().Task, caller.Token));
        }, TestContext.Current.CancellationToken, installBaseline: false);
    }

    [Fact]
    public async Task A_completed_contender_cannot_satisfy_the_barrier()
    {
        await SqlContractFixture.RunAsync(async (fixture, cancellation) =>
        {
            var observer = await fixture.OpenConnectionAsync();
            await Should.ThrowAsync<InvalidOperationException>(() => SqlInterleavingBarrier.WaitForBlockedAsync(
                observer, observer.ProcessID + 1, observer.ProcessID, Task.CompletedTask, cancellation));
        }, TestContext.Current.CancellationToken, installBaseline: false);
    }

    [Fact]
    public async Task Failed_connection_initialization_closes_the_unregistered_backend()
    {
        await SqlContractFixture.RunAsync(async (fixture, cancellation) =>
        {
            var observer = await fixture.OpenConnectionAsync();
            await Should.ThrowAsync<PostgresException>(() => fixture.OpenConnectionAsync(initializeSql: "select 1/0;"));
            fixture.Connections.Count.ShouldBe(1);
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
            deadline.CancelAfter(TimeSpan.FromSeconds(5));
            while (await ScalarAsync<long>(observer, $"select count(*) from pg_stat_activity where application_name = '{fixture.Schema}';", deadline.Token) != 1)
                await Task.Delay(TimeSpan.FromMilliseconds(20), deadline.Token);
        }, TestContext.Current.CancellationToken, installBaseline: false);
    }

    [Fact]
    public async Task Failed_schema_setup_rolls_back_and_removes_only_its_allocated_schema()
    {
        string? schema = null;
        await Should.ThrowAsync<PostgresException>(() => SqlContractFixture.CreateAsync(
            TestContext.Current.CancellationToken, installBaseline: false,
            setupSql: "create table setup_probe(id int); select 1/0;", schemaAllocated: value => schema = value));
        schema.ShouldNotBeNull();
        await SqlContractFixture.RunAsync(async (fixture, cancellation) =>
        {
            var observer = await fixture.OpenConnectionAsync();
            (await ScalarAsync<bool>(observer, $"select exists(select 1 from pg_namespace where nspname = '{schema}');", cancellation)).ShouldBeFalse();
        }, TestContext.Current.CancellationToken, installBaseline: false);
    }

    [Fact]
    public async Task Body_failure_is_preserved_and_its_uncommitted_transaction_and_schema_are_removed()
    {
        string? schema = null;
        var expected = new InvalidOperationException("intentional fixture body failure");
        Exception actual = await Should.ThrowAsync<InvalidOperationException>(() => SqlContractFixture.RunAsync(async (fixture, cancellation) =>
        {
            schema = fixture.Schema;
            var connection = await fixture.OpenConnectionAsync();
            await fixture.ExecuteAsync(connection, "create table rollback_probe(id int);");
            var transaction = await fixture.BeginTransactionAsync(connection);
            await fixture.ExecuteAsync(connection, "insert into rollback_probe values(1);", transaction);
            throw expected;
        }, TestContext.Current.CancellationToken, installBaseline: false));
        ReferenceEquals(expected, actual).ShouldBeTrue();
        schema.ShouldNotBeNull();
        var settings = new NpgsqlConnectionStringBuilder(DeferredSqlProcedureContractSettings.ConnectionString!)
        { Pooling = false, Timeout = 5, CommandTimeout = 5, SearchPath = "public" };
        await using var admin = new NpgsqlConnection(settings.ConnectionString);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(10));
        await admin.OpenAsync(deadline.Token);
        (await ScalarAsync<bool>(admin, $"select exists(select 1 from pg_namespace where nspname = '{schema}');", deadline.Token)).ShouldBeFalse();
    }

    private static async Task<T> ScalarAsync<T>(NpgsqlConnection connection, string sql, CancellationToken cancellation)
    {
        await using var command = new NpgsqlCommand(sql, connection) { CommandTimeout = 5 };
        object? value = await command.ExecuteScalarAsync(cancellation);
        value.ShouldBeOfType<T>();
        return (T)value!;
    }
}
