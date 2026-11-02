using Npgsql;
using Shouldly;
using treehammock.Tests.SqlContracts.Support;

namespace treehammock.Tests.Integration.Database;

[Trait("Suite", "SqlContracts")]
public class SessionConcurrencyProcedureContractTests
{
    [Fact]
    public async Task Set_session_serializes_concurrent_session_creation_for_the_same_account()
    {
        await SqlContractFixture.RunAsync(async (fixture, cancellation) =>
        {
            var setupConnection = await fixture.OpenConnectionAsync();
            Guid accountId = Guid.NewGuid();
            byte[] hashedPassword = Enumerable.Repeat((byte)1, 128).ToArray();
            byte[] saltOne = Enumerable.Repeat((byte)2, 64).ToArray();
            byte[] siv = Enumerable.Repeat((byte)3, 32).ToArray();
            byte[] nonce = Enumerable.Repeat((byte)4, 16).ToArray();
            byte[] firstRefreshToken = Enumerable.Repeat((byte)5, 64).ToArray();
            byte[] secondRefreshToken = Enumerable.Repeat((byte)6, 64).ToArray();
            Guid firstSecurityStamp = Guid.Parse("11111111-1111-1111-1111-111111111111");
            Guid secondSecurityStamp = Guid.Parse("22222222-2222-2222-2222-222222222222");

            await ExecuteAsync(
                setupConnection,
                cancellation,
                """
                insert into accounts(
                    account_id, email_address, username, hashed_password, web_key, salt_one, siv, nonce,
                    login_failures, verify_status, features, two_factor_auth_method)
                values (
                    @accountId, 'concurrent-session@example.com', 'concurrent-session-reader', @hashedPassword, 'concurrent-session-web-key', @saltOne, @siv, @nonce,
                    0, 1, 0, 0);
                """,
                ("accountId", accountId),
                ("hashedPassword", hashedPassword),
                ("saltOne", saltOne),
                ("siv", siv),
                ("nonce", nonce));

            Guid accountSecurityStamp = await QueryGuidAsync(
                setupConnection,
                cancellation,
                "select security_stamp from accounts where account_id = @accountId;",
                ("accountId", accountId));

            var firstConnection = await fixture.OpenConnectionAsync();
            NpgsqlTransaction firstTransaction = await fixture.BeginTransactionAsync(firstConnection);

            (short firstResult, string firstCode) = await QueryShortStatusAsync(
                firstConnection,
                firstTransaction,
                cancellation,
                """
                select result, code from set_session(
                    @accessTokenHash, @accountId, @refreshToken, @refreshes, @limit,
                    @createdOn, @sessionLifespan, @accessExpiration, @sessionExpiration, @cutOff, @features, @securityStamp, @accountSecurityStamp);
                """,
                ("accessTokenHash", "concurrent-session-first"),
                ("accountId", accountId),
                ("refreshToken", firstRefreshToken),
                ("refreshes", (short)0),
                ("limit", (short)5),
                ("createdOn", DateTimeOffset.UtcNow),
                ("sessionLifespan", TimeSpan.FromDays(7)),
                ("accessExpiration", DateTimeOffset.UtcNow.AddMinutes(10)),
                ("sessionExpiration", DateTimeOffset.UtcNow.AddDays(7)),
                ("cutOff", DateTimeOffset.UtcNow.AddDays(7)),
                ("features", (short)0),
                ("securityStamp", firstSecurityStamp),
                ("accountSecurityStamp", accountSecurityStamp));

            firstResult.ShouldBe((short)1);
            firstCode.ShouldBe("SUCCESSFUL");

            var secondConnection = await fixture.OpenConnectionAsync();
            NpgsqlTransaction secondTransaction = await fixture.BeginTransactionAsync(secondConnection);

            Task<(short Result, string Code)> secondSetSessionTask = fixture.Observe(QueryShortStatusAsync(
                secondConnection,
                secondTransaction,
                cancellation,
                """
                select result, code from set_session(
                    @accessTokenHash, @accountId, @refreshToken, @refreshes, @limit,
                    @createdOn, @sessionLifespan, @accessExpiration, @sessionExpiration, @cutOff, @features, @securityStamp, @accountSecurityStamp);
                """,
                ("accessTokenHash", "concurrent-session-second"),
                ("accountId", accountId),
                ("refreshToken", secondRefreshToken),
                ("refreshes", (short)0),
                ("limit", (short)5),
                ("createdOn", DateTimeOffset.UtcNow.AddMinutes(1)),
                ("sessionLifespan", TimeSpan.FromDays(7)),
                ("accessExpiration", DateTimeOffset.UtcNow.AddMinutes(20)),
                ("sessionExpiration", DateTimeOffset.UtcNow.AddDays(7)),
                ("cutOff", DateTimeOffset.UtcNow.AddDays(7)),
                ("features", (short)0),
                ("securityStamp", secondSecurityStamp),
                ("accountSecurityStamp", accountSecurityStamp)));

            SqlLockObservation observation = await SqlInterleavingBarrier.WaitForBlockedAsync(
                setupConnection, secondConnection.ProcessID, firstConnection.ProcessID,
                secondSetSessionTask, cancellation);
            observation.BlockerPid.ShouldBe(firstConnection.ProcessID);
            observation.ContenderPid.ShouldBe(secondConnection.ProcessID);
            Console.WriteLine($"COR01 run={fixture.RunId} schema={fixture.Schema} contender={observation.ContenderPid} blocker={observation.BlockerPid} wait={observation.WaitEvent} xid={observation.TransactionId}");
            await firstTransaction.CommitAsync(cancellation);

            (short secondResult, string secondCode) = await secondSetSessionTask.WaitAsync(cancellation);
            secondResult.ShouldBe((short)1);
            secondCode.ShouldBe("SUCCESSFUL");
            await secondTransaction.CommitAsync(cancellation);

            long activeSessionCount = await QueryLongAsync(
                setupConnection,
                cancellation,
                "select count(*) from sessions where account_id = @accountId and session_expiration > now();",
                ("accountId", accountId));
            activeSessionCount.ShouldBe(1);

            string currentActiveSession = await QueryStringAsync(
                setupConnection,
                cancellation,
                "select active_access_token_hash from get_current_active_session_hash(@accountId);",
                ("accountId", accountId));
            currentActiveSession.ShouldBe("concurrent-session-second");

            (short staleTrustStatus, string staleTrustCode) = await QueryShortStatusAsync(
                setupConnection,
                null,
                cancellation,
                "select status, code from validate_cached_session_trust(@accessTokenHash, @accountId, @securityStamp, @accountSecurityStamp);",
                ("accessTokenHash", "concurrent-session-first"),
                ("accountId", accountId),
                ("securityStamp", firstSecurityStamp),
                ("accountSecurityStamp", accountSecurityStamp));
            staleTrustStatus.ShouldBe((short)5);
            staleTrustCode.ShouldBe("SESSION_EXPIRED");

            (short currentTrustStatus, string currentTrustCode) = await QueryShortStatusAsync(
                setupConnection,
                null,
                cancellation,
                "select status, code from validate_cached_session_trust(@accessTokenHash, @accountId, @securityStamp, @accountSecurityStamp);",
                ("accessTokenHash", "concurrent-session-second"),
                ("accountId", accountId),
                ("securityStamp", secondSecurityStamp),
                ("accountSecurityStamp", accountSecurityStamp));
            currentTrustStatus.ShouldBe((short)1);
            currentTrustCode.ShouldBe("VALID");
        }, TestContext.Current.CancellationToken);
    }

    private static async Task ExecuteAsync(NpgsqlConnection connection, CancellationToken cancellation, string sql, params (string Name, object? Value)[] parameters)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        AddParameters(command, parameters);
        await command.ExecuteNonQueryAsync(cancellation);
    }

    private static async Task<Guid> QueryGuidAsync(NpgsqlConnection connection, CancellationToken cancellation, string sql, params (string Name, object? Value)[] parameters)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        AddParameters(command, parameters);
        object? result = await command.ExecuteScalarAsync(cancellation);
        result.ShouldNotBeNull();
        return (Guid)result;
    }

    private static async Task<long> QueryLongAsync(NpgsqlConnection connection, CancellationToken cancellation, string sql, params (string Name, object? Value)[] parameters)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        AddParameters(command, parameters);
        object? result = await command.ExecuteScalarAsync(cancellation);
        result.ShouldNotBeNull();
        return (long)result;
    }

    private static async Task<string> QueryStringAsync(NpgsqlConnection connection, CancellationToken cancellation, string sql, params (string Name, object? Value)[] parameters)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        AddParameters(command, parameters);
        object? result = await command.ExecuteScalarAsync(cancellation);
        result.ShouldNotBeNull();
        return (string)result;
    }

    private static async Task<(short Result, string Code)> QueryShortStatusAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction? transaction,
        CancellationToken cancellation,
        string sql,
        params (string Name, object? Value)[] parameters)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        if (transaction is not null)
        {
            command.Transaction = transaction;
        }

        AddParameters(command, parameters);

        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellation);
        (await reader.ReadAsync(cancellation)).ShouldBeTrue();

        return (reader.GetInt16(0), reader.GetString(1));
    }

    private static void AddParameters(NpgsqlCommand command, params (string Name, object? Value)[] parameters)
    {
        foreach ((string name, object? value) in parameters)
        {
            command.Parameters.AddWithValue(name, value ?? DBNull.Value);
        }
    }

}
