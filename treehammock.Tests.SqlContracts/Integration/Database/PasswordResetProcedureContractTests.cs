using treehammock.Tests.SqlContracts.Support;

using Npgsql;
using Shouldly;

namespace treehammock.Tests.Integration.Database;

[Trait("Suite", "SqlContracts")]
public class PasswordResetProcedureContractTests
{
    [Fact]
    public async Task Password_reset_sql_lifecycle_is_account_bound_single_active_and_atomic_on_promotion()
    {
        if (!DeferredSqlProcedureContractSettings.ShouldRun())
        {
            throw new InvalidOperationException(DeferredSqlProcedureContractSettings.SkipReason);
        }

        string connectionString = DeferredSqlProcedureContractSettings.ConnectionString!;
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();

        string schema = "password_reset_contract_" + Guid.NewGuid().ToString("N");

        try
        {
            await ExecuteAsync(connection, $"create schema {schema};");
            await ExecuteAsync(connection, $"set search_path to {schema};");
            await ExecuteAsync(connection, File.ReadAllText(BaselinePath()));

            Guid accountId = Guid.NewGuid();
            byte[] oldHashedPassword = Enumerable.Repeat((byte)1, 128).ToArray();
            byte[] oldSaltOne = Enumerable.Repeat((byte)2, 64).ToArray();
            byte[] oldSiv = Enumerable.Repeat((byte)3, 32).ToArray();
            byte[] oldNonce = Enumerable.Repeat((byte)4, 16).ToArray();
            byte[] oldRefreshToken = Enumerable.Repeat((byte)5, 64).ToArray();

            await ExecuteAsync(
                connection,
                """
                insert into accounts(
                    account_id, email_address, username, hashed_password, web_key, salt_one, siv, nonce,
                    login_failures, verify_status, features, two_factor_auth_method)
                values (
                    @accountId, 'reset-reader@example.com', 'reset-reader', @hashedPassword, 'reset-web-key', @saltOne, @siv, @nonce,
                    4, 1, 0, 0);
                """,
                ("accountId", accountId),
                ("hashedPassword", oldHashedPassword),
                ("saltOne", oldSaltOne),
                ("siv", oldSiv),
                ("nonce", oldNonce));

            Guid accountSecurityStamp = await QueryGuidAsync(
                connection,
                "select security_stamp from accounts where account_id = @accountId;",
                ("accountId", accountId));

            Guid resetId1 = Guid.NewGuid();
            PasswordResetCreateResult firstCreate = await QueryCreateAsync(
                connection,
                """
                select *
                  from create_password_reset_request(
                    @resetId, @accountId, 'email', 'email', 'hash-one', 1,
                    'fingerprint-one', 'r***r@example.com', true, false, now() + interval '10 minutes',
                    5, cast(@requestedByIp as inet), 'unit-test', @accountSecurityStamp);
                """,
                ("resetId", resetId1),
                ("accountId", accountId),
                ("requestedByIp", "127.0.0.1"),
                ("accountSecurityStamp", accountSecurityStamp));

            firstCreate.Result.ShouldBeTrue();
            firstCreate.Code.ShouldBe("PASSWORD_RESET_REQUEST_CREATED");
            firstCreate.PasswordResetRequestId.ShouldBe(resetId1);
            firstCreate.AccountId.ShouldBe(accountId);

            PasswordResetFinalizeLookupResult firstLookup = await QueryLookupAsync(
                connection,
                "select * from get_password_reset_request_for_finalize(@resetId);",
                ("resetId", resetId1));
            firstLookup.Result.ShouldBeTrue();
            firstLookup.Code.ShouldBe("PASSWORD_RESET_READY");
            firstLookup.AccountId.ShouldBe(accountId);
            firstLookup.KeyCodeHash.ShouldBe("hash-one");

            await Should.ThrowAsync<PostgresException>(async () =>
            {
                await ExecuteAsync(
                    connection,
                    """
                    insert into password_reset_requests(
                        factor_policy_version,password_reset_request_id, account_id, method, delivery_channel, key_code_hash,
                        key_code_hash_version, destination_fingerprint, destination_masked, requires_totp,
                        expires_at, max_attempts, account_security_stamp_at_request)
                    values(
                        cor13_reset_policy(@accountId),@resetId, @accountId, 'email', 'email', 'manual-hash', 1,
                        'manual-fingerprint', 'r***r@example.com', false, now() + interval '10 minutes',
                        5, @accountSecurityStamp);
                    """,
                    ("resetId", Guid.NewGuid()),
                    ("accountId", accountId),
                    ("accountSecurityStamp", accountSecurityStamp));
            });

            Guid resetIdDeliveryFailure = Guid.NewGuid();
            PasswordResetCreateResult deliveryFailureCreate = await QueryCreateAsync(
                connection,
                """
                select *
                  from create_password_reset_request(
                    @resetId, @accountId, 'email', 'email', 'hash-delivery-failure', 1,
                    'fingerprint-delivery-failure', 'r***r@example.com', true, false, now() + interval '10 minutes',
                    5, null::inet, 'unit-test', @accountSecurityStamp);
                """,
                ("resetId", resetIdDeliveryFailure),
                ("accountId", accountId),
                ("accountSecurityStamp", accountSecurityStamp));
            deliveryFailureCreate.Result.ShouldBeTrue();

            PasswordResetCancelResult cancelledDeliveryFailure = await QueryCancelAsync(
                connection,
                "select * from cancel_password_reset_request(@resetId, now(), 'PASSWORD_RESET_DELIVERY_FAILED');",
                ("resetId", resetIdDeliveryFailure));
            cancelledDeliveryFailure.Result.ShouldBeTrue();
            cancelledDeliveryFailure.Code.ShouldBe("PASSWORD_RESET_DELIVERY_FAILED");
            cancelledDeliveryFailure.AccountId.ShouldBe(accountId);
            cancelledDeliveryFailure.CancelledAt.ShouldNotBeNull();
            (await QueryDateTimeOffsetOrNullAsync(connection, "select cancelled_at from password_reset_requests where password_reset_request_id = @resetId;", ("resetId", resetIdDeliveryFailure))).ShouldNotBeNull();
            (await QueryIntAsync(connection, "select count(*) from password_reset_events where password_reset_request_id = @resetId and event_type = 'password_reset_delivery_failed';", ("resetId", resetIdDeliveryFailure))).ShouldBe(1);

            await ExecuteAsync(
                connection,
                """
                insert into two_factor_authentications(
                    two_factor_index, account_id, method, verified, phone_number, phone_country_code, created_on, expiration)
                values(1, @accountId, 2, true, '5555551234', '+1', now(), now() + interval '1 day');
                """,
                ("accountId", accountId));

            Guid resetId2 = Guid.NewGuid();
            PasswordResetCreateResult secondCreate = await QueryCreateAsync(
                connection,
                """
                select *
                  from create_password_reset_request(
                    @resetId, @accountId, 'sms', 'sms', 'hash-two', 1,
                    'fingerprint-two', '***-***-1234', true, false, now() + interval '10 minutes',
                    2, null::inet, 'unit-test', @accountSecurityStamp);
                """,
                ("resetId", resetId2),
                ("accountId", accountId),
                ("accountSecurityStamp", accountSecurityStamp));

            secondCreate.Result.ShouldBeTrue();
            secondCreate.Code.ShouldBe("PASSWORD_RESET_REQUEST_CREATED");
            (await QueryIntAsync(connection, "select count(*) from password_reset_requests where account_id = @accountId and consumed_at is null and cancelled_at is null;", ("accountId", accountId))).ShouldBe(1);
            (await QueryDateTimeOffsetOrNullAsync(connection, "select cancelled_at from password_reset_requests where password_reset_request_id = @resetId;", ("resetId", resetId1))).ShouldNotBeNull();

            PasswordResetFailedAttemptResult firstFailedAttempt = await QueryFailedAttemptAsync(
                connection,
                "select * from register_password_reset_failed_attempt(@resetId, now());",
                ("resetId", resetId2));
            firstFailedAttempt.Result.ShouldBeTrue();
            firstFailedAttempt.Code.ShouldBe("PASSWORD_RESET_ATTEMPT_RECORDED");
            firstFailedAttempt.AttemptCount.ShouldBe(1);
            firstFailedAttempt.CancelledAt.ShouldBeNull();

            PasswordResetFailedAttemptResult exhaustedAttempt = await QueryFailedAttemptAsync(
                connection,
                "select * from register_password_reset_failed_attempt(@resetId, now());",
                ("resetId", resetId2));
            exhaustedAttempt.Result.ShouldBeFalse();
            exhaustedAttempt.Code.ShouldBe("PASSWORD_RESET_ATTEMPTS_EXCEEDED");
            exhaustedAttempt.AttemptCount.ShouldBe(2);
            exhaustedAttempt.CancelledAt.ShouldNotBeNull();

            await ExecuteAsync(
                connection,
                """
                insert into two_factor_authentications(two_factor_index,account_id,method,verified,required,created_on,expiration,totp_secret_ciphertext,totp_secret_nonce,totp_secret_tag,totp_secret_version,totp_provider_type,totp_key_id,totp_enrollment_id,totp_algorithm,totp_digits,totp_period_seconds,totp_clock_skew_steps) values(2,@accountId,3,true,true,now(),now() + interval '1 day',decode(repeat('01',20),'hex'),decode(repeat('01',12),'hex'),decode(repeat('01',16),'hex'),2,1,'fixture',gen_random_uuid(),'SHA1',6,30,1);
                """,
                ("accountId", accountId));

            Guid resetId3 = Guid.NewGuid();
            PasswordResetCreateResult thirdCreate = await QueryCreateAsync(
                connection,
                """
                select *
                  from create_password_reset_request(
                    @resetId, @accountId, 'email', 'email', 'hash-three', 1,
                    'fingerprint-three', 'r***r@example.com', true, false, now() + interval '10 minutes',
                    5, null::inet, 'unit-test', @accountSecurityStamp);
                """,
                ("resetId", resetId3),
                ("accountId", accountId),
                ("accountSecurityStamp", accountSecurityStamp));
            thirdCreate.Result.ShouldBeTrue();

            await ExecuteAsync(
                connection,
                """
                insert into sessions(
                    access_token_hash, account_id, refresh_token, refreshes, refresh_limit, created_on,
                    session_lifespan, access_expiration, session_expiration, features, account_security_stamp)
                values(
                    'password-reset-session', @accountId, @refreshToken, 0, 5, now(),
                    interval '7 days', now() + interval '10 minutes', now() + interval '1 hour', 0, @accountSecurityStamp);
                """,
                ("accountId", accountId),
                ("refreshToken", oldRefreshToken),
                ("accountSecurityStamp", accountSecurityStamp));

            byte[] newHashedPassword = Enumerable.Repeat((byte)9, 128).ToArray();
            byte[] newSaltOne = Enumerable.Repeat((byte)8, 64).ToArray();
            byte[] newSiv = Enumerable.Repeat((byte)7, 32).ToArray();
            byte[] newNonce = Enumerable.Repeat((byte)6, 16).ToArray();
            Guid newSecurityStamp = Guid.NewGuid();

            var authorization = await Cor13ResetSql.BootstrapStateAsync(connection,accountId.ToString(),resetId3.ToString(),"procedure-authorization",TestContext.Current.CancellationToken);
            (await QueryBoolAsync(connection,Cor13ResetSql.Promote(resetId3.ToString(),accountId.ToString(),authorization.Session,authorization.Challenge,"procedure-authorization"))).ShouldBeFalse();
            var selected = await Cor13ResetSql.TransitionStateAsync(connection,"procedure-authorization",2,authorization,Cor13ResetSql.Select(3),TestContext.Current.CancellationToken);
            (await QueryBoolAsync(connection,Cor13ResetSql.Promote(resetId3.ToString(),accountId.ToString(),selected.Session,selected.Challenge,"procedure-authorization"))).ShouldBeFalse();
            // A stale selected-proof version cannot complete the newly selected authenticator path.
            (await QueryBoolAsync(connection,Cor13ResetSql.Transition("procedure-authorization",5,authorization.Session,authorization.Challenge,Cor13ResetSql.Valid()))).ShouldBeFalse();
            var complete = await Cor13ResetSql.TransitionStateAsync(connection,"procedure-authorization",5,selected,Cor13ResetSql.Valid(),TestContext.Current.CancellationToken);
            (await QueryBoolAsync(connection,Cor13ResetSql.Promote(resetId3.ToString(),accountId.ToString(),selected.Session,selected.Challenge,"procedure-authorization"))).ShouldBeFalse();
            (await QueryGuidAsync(connection,"select security_stamp from accounts where account_id=@accountId",("accountId",accountId))).ShouldBe(accountSecurityStamp);
            (await QueryBytesAsync(connection,"select hashed_password from accounts where account_id=@accountId",("accountId",accountId))).ShouldBe(oldHashedPassword);
            (await QueryDateTimeOffsetOrNullAsync(connection,"select consumed_at from password_reset_requests where password_reset_request_id=@resetId",("resetId",resetId3))).ShouldBeNull();
            PasswordResetPromoteResult promoted = await QueryPromoteAsync(
                connection,
                """
                select *
                  from promote_password_reset(
                    @resetId, @accountId, @hashedPassword, @saltOne, @siv, @nonce,
                    @newSecurityStamp, now(), 'procedure-authorization',@sessionVersion::bigint,@challengeVersion::bigint);
                """,
                ("resetId", resetId3),
                ("accountId", accountId),
                ("hashedPassword", newHashedPassword),
                ("saltOne", newSaltOne),
                ("siv", newSiv),
                ("nonce", newNonce),
                ("newSecurityStamp", newSecurityStamp),
                ("sessionVersion", complete.Session),
                ("challengeVersion", complete.Challenge));

            promoted.Result.ShouldBeTrue();
            promoted.Code.ShouldBe("PASSWORD_RESET_COMPLETED");
            promoted.AccountId.ShouldBe(accountId);
            promoted.AccountSecurityStamp.ShouldBe(newSecurityStamp);
            promoted.ConsumedAt.ShouldNotBeNull();

            (await QueryGuidAsync(connection, "select security_stamp from accounts where account_id = @accountId;", ("accountId", accountId))).ShouldBe(newSecurityStamp);
            (await QueryBytesAsync(connection, "select hashed_password from accounts where account_id = @accountId;", ("accountId", accountId))).ShouldBe(newHashedPassword);
            (await QueryDateTimeOffsetOrNullAsync(connection, "select cut_off from accounts where account_id = @accountId;", ("accountId", accountId))).ShouldBeNull();
            (await QueryDateTimeOffsetOrNullAsync(connection, "select cut_off from sessions where access_token_hash = @accessTokenHash;", ("accessTokenHash", "password-reset-session"))).ShouldNotBeNull();
            (await QueryIntAsync(connection, "select login_failures from accounts where account_id = @accountId;", ("accountId", accountId))).ShouldBe(0);
            (await QueryIntAsync(connection, "select count(*) from get_session(@accessTokenHash);", ("accessTokenHash", "password-reset-session"))).ShouldBe(0);
        }
        finally
        {
            await ExecuteAsync(connection, $"drop schema if exists {schema} cascade;");
        }
    }


    [Fact]
    public async Task Password_reset_totp_lookup_requires_verified_authenticator_app_secret_and_rejects_replay()
    {
        if (!DeferredSqlProcedureContractSettings.ShouldRun())
        {
            throw new InvalidOperationException(DeferredSqlProcedureContractSettings.SkipReason);
        }

        string connectionString = DeferredSqlProcedureContractSettings.ConnectionString!;
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();

        string schema = "password_reset_totp_contract_" + Guid.NewGuid().ToString("N");

        try
        {
            await ExecuteAsync(connection, $"create schema {schema};");
            await ExecuteAsync(connection, $"set search_path to {schema};");
            await ExecuteAsync(connection, File.ReadAllText(BaselinePath()));

            Guid accountId = Guid.NewGuid();
            await ExecuteAsync(
                connection,
                """
                insert into accounts(
                    account_id, email_address, username, hashed_password, web_key, salt_one, siv, nonce,
                    login_failures, verify_status, features, two_factor_auth_method)
                values (
                    @accountId, 'totp-reader@example.com', 'totp-reader', @hashedPassword, 'totp-web-key-' || gen_random_uuid()::text, @saltOne, @siv, @nonce,
                    0, 1, 0, 3);
                """,
                ("accountId", accountId),
                ("hashedPassword", Enumerable.Repeat((byte)1, 128).ToArray()),
                ("saltOne", Enumerable.Repeat((byte)2, 64).ToArray()),
                ("siv", Enumerable.Repeat((byte)3, 32).ToArray()),
                ("nonce", Enumerable.Repeat((byte)4, 16).ToArray()));

            PasswordResetTotpEnrollmentResult missing = await QueryTotpEnrollmentAsync(
                connection,
                "select * from get_password_reset_totp_enrollment(@accountId, now());",
                ("accountId", accountId));
            missing.Found.ShouldBeFalse();

            await ExecuteAsync(
                connection,
                """
                insert into two_factor_authentications(two_factor_index,account_id,method,verified,priority,required,totp_secret_ciphertext,totp_secret_nonce,totp_secret_tag,totp_secret_version,totp_provider_type,totp_key_id,totp_enrollment_id,totp_algorithm,totp_digits,totp_period_seconds,totp_clock_skew_steps) values(3,@accountId,3,true,0,true,decode(repeat('01',20),'hex'),decode(repeat('01',12),'hex'),decode(repeat('01',16),'hex'),2,1,'fixture',gen_random_uuid(),'SHA1',6,30,1);
                """,
                ("accountId", accountId));

            PasswordResetTotpEnrollmentResult found = await QueryTotpEnrollmentAsync(
                connection,
                "select * from get_password_reset_totp_enrollment(@accountId, now());",
                ("accountId", accountId));
            found.Found.ShouldBeTrue();
            found.AccountId.ShouldBe(accountId);
            found.TwoFactorIndex.ShouldBe(3L);
            found.Method.ShouldBe((short)3);
            found.LastUsedStep.ShouldBeNull();
            found.EnrollmentId.ShouldNotBeNull();
            found.EnrollmentId.ShouldNotBe(Guid.Empty);
            var wrongEnrollment = await QueryTotpStepAsync(connection,
                "select * from mark_password_reset_totp_step_used(@accountId,3::bigint,1000,@enrollmentId)",
                ("accountId",accountId),("enrollmentId",Guid.NewGuid()));
            wrongEnrollment.Result.ShouldBeFalse();wrongEnrollment.Code.ShouldBe("TOTP_ENROLLMENT_NOT_FOUND");
            (await QueryTotpEnrollmentAsync(connection,"select * from get_password_reset_totp_enrollment(@accountId,now())",("accountId",accountId))).LastUsedStep.ShouldBeNull();

            PasswordResetTotpStepResult accepted = await QueryTotpStepAsync(
                connection,
                "select * from mark_password_reset_totp_step_used(@accountId, 3::bigint, 1000, @enrollmentId);",
                ("accountId", accountId), ("enrollmentId", found.EnrollmentId!.Value));
            accepted.Result.ShouldBeTrue();
            accepted.Code.ShouldBe("TOTP_STEP_ACCEPTED");

            PasswordResetTotpStepResult sameStep = await QueryTotpStepAsync(
                connection,
                "select * from mark_password_reset_totp_step_used(@accountId, 3::bigint, 1000, @enrollmentId);",
                ("accountId", accountId), ("enrollmentId", found.EnrollmentId!.Value));
            sameStep.Result.ShouldBeFalse();
            sameStep.Code.ShouldBe("TOTP_REPLAY_DETECTED");

            PasswordResetTotpStepResult olderStep = await QueryTotpStepAsync(
                connection,
                "select * from mark_password_reset_totp_step_used(@accountId, 3::bigint, 999, @enrollmentId);",
                ("accountId", accountId), ("enrollmentId", found.EnrollmentId!.Value));
            olderStep.Result.ShouldBeFalse();
            olderStep.Code.ShouldBe("TOTP_REPLAY_DETECTED");

            PasswordResetTotpStepResult newerStep = await QueryTotpStepAsync(
                connection,
                "select * from mark_password_reset_totp_step_used(@accountId, 3::bigint, 1001, @enrollmentId);",
                ("accountId", accountId), ("enrollmentId", found.EnrollmentId!.Value));
            newerStep.Result.ShouldBeTrue();
            newerStep.Code.ShouldBe("TOTP_STEP_ACCEPTED");

            long lastUsedStep = await QueryLongAsync(
                connection,
                "select totp_last_used_step from two_factor_authentications where account_id = @accountId and two_factor_index = 3;",
                ("accountId", accountId));
            lastUsedStep.ShouldBe(1001);
        }
        finally
        {
            await ExecuteAsync(connection, $"drop schema if exists {schema} cascade;");
        }
    }


    [Fact]
    public async Task Password_reset_request_rate_limit_enforces_cooldown_window_and_block()
    {
        if (!DeferredSqlProcedureContractSettings.ShouldRun())
        {
            throw new InvalidOperationException(DeferredSqlProcedureContractSettings.SkipReason);
        }

        string connectionString = DeferredSqlProcedureContractSettings.ConnectionString!;
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();

        string schema = "password_reset_rate_limit_contract_" + Guid.NewGuid().ToString("N");

        try
        {
            await ExecuteAsync(connection, $"create schema {schema};");
            await ExecuteAsync(connection, $"set search_path to {schema};");
            await ExecuteAsync(connection, File.ReadAllText(BaselinePath()));

            PasswordResetRateLimitResult first = await QueryRateLimitAsync(
                connection,
                """
                select *
                  from register_password_reset_request_rate_limit(
                    'ip:test-password-reset-rate-limit',
                    timestamp with time zone '2026-01-01 00:00:00+00',
                    interval '24 hours',
                    2,
                    interval '60 seconds',
                    interval '30 minutes');
                """);
            first.Result.ShouldBeTrue();
            first.Code.ShouldBe("PASSWORD_RESET_RATE_LIMIT_OK");
            first.RequestCount.ShouldBe(1);

            PasswordResetRateLimitResult cooldown = await QueryRateLimitAsync(
                connection,
                """
                select *
                  from register_password_reset_request_rate_limit(
                    'ip:test-password-reset-rate-limit',
                    timestamp with time zone '2026-01-01 00:00:10+00',
                    interval '24 hours',
                    2,
                    interval '60 seconds',
                    interval '30 minutes');
                """);
            cooldown.Result.ShouldBeFalse();
            cooldown.Code.ShouldBe("PASSWORD_RESET_REQUEST_COOLDOWN");
            cooldown.RetryAfterSeconds.ShouldNotBeNull();
            cooldown.RetryAfterSeconds!.Value.ShouldBeGreaterThan(0);

            PasswordResetRateLimitResult second = await QueryRateLimitAsync(
                connection,
                """
                select *
                  from register_password_reset_request_rate_limit(
                    'ip:test-password-reset-rate-limit',
                    timestamp with time zone '2026-01-01 00:01:01+00',
                    interval '24 hours',
                    2,
                    interval '60 seconds',
                    interval '30 minutes');
                """);
            second.Result.ShouldBeTrue();
            second.Code.ShouldBe("PASSWORD_RESET_RATE_LIMIT_OK");
            second.RequestCount.ShouldBe(2);

            PasswordResetRateLimitResult blocked = await QueryRateLimitAsync(
                connection,
                """
                select *
                  from register_password_reset_request_rate_limit(
                    'ip:test-password-reset-rate-limit',
                    timestamp with time zone '2026-01-01 00:02:02+00',
                    interval '24 hours',
                    2,
                    interval '60 seconds',
                    interval '30 minutes');
                """);
            blocked.Result.ShouldBeFalse();
            blocked.Code.ShouldBe("PASSWORD_RESET_RATE_LIMITED");
            blocked.BlockedUntil.ShouldNotBeNull();

            int deleted = await QueryIntAsync(
                connection,
                "select deleted_count from cleanup_password_reset_rate_limits(timestamp with time zone '2026-02-01 00:00:00+00', interval '7 days');");
            deleted.ShouldBe(1);
        }
        finally
        {
            await ExecuteAsync(connection, $"drop schema if exists {schema} cascade;");
        }
    }

    private static async Task ExecuteAsync(NpgsqlConnection connection, string sql, params (string Name, object? Value)[] parameters)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        AddParameters(command, parameters);
        await command.ExecuteNonQueryAsync();
    }

    private static async Task<bool> QueryBoolAsync(NpgsqlConnection connection, string sql)
    {
        await using var command = new NpgsqlCommand(sql,connection);
        return (bool)(await command.ExecuteScalarAsync(TestContext.Current.CancellationToken))!;
    }

    private static async Task<Guid> QueryGuidAsync(NpgsqlConnection connection, string sql, params (string Name, object? Value)[] parameters)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        AddParameters(command, parameters);
        object? result = await command.ExecuteScalarAsync();
        result.ShouldNotBeNull();
        return (Guid)result;
    }

    private static async Task<int> QueryIntAsync(NpgsqlConnection connection, string sql, params (string Name, object? Value)[] parameters)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        AddParameters(command, parameters);
        object? result = await command.ExecuteScalarAsync();
        result.ShouldNotBeNull();
        return Convert.ToInt32(result);
    }

    private static async Task<long> QueryLongAsync(NpgsqlConnection connection, string sql, params (string Name, object? Value)[] parameters)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        AddParameters(command, parameters);
        object? result = await command.ExecuteScalarAsync();
        result.ShouldNotBeNull();
        return Convert.ToInt64(result);
    }

    private static async Task<byte[]> QueryBytesAsync(NpgsqlConnection connection, string sql, params (string Name, object? Value)[] parameters)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        AddParameters(command, parameters);
        object? result = await command.ExecuteScalarAsync();
        result.ShouldNotBeNull();
        return (byte[])result;
    }

    private static async Task<DateTimeOffset?> QueryDateTimeOffsetOrNullAsync(NpgsqlConnection connection, string sql, params (string Name, object? Value)[] parameters)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        AddParameters(command, parameters);
        object? result = await command.ExecuteScalarAsync();
        if (result is null || result is DBNull)
        {
            return null;
        }

        return result switch
        {
            DateTimeOffset dateTimeOffset => dateTimeOffset,
            DateTime dateTime => new DateTimeOffset(DateTime.SpecifyKind(dateTime, DateTimeKind.Utc)),
            _ => throw new InvalidOperationException($"Unexpected timestamp value type {result.GetType().FullName}.")
        };
    }

    private static async Task<PasswordResetCreateResult> QueryCreateAsync(NpgsqlConnection connection, string sql, params (string Name, object? Value)[] parameters)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        AddParameters(command, parameters);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync();
        (await reader.ReadAsync()).ShouldBeTrue();

        return new PasswordResetCreateResult(
            reader.GetBoolean(0),
            reader.GetString(1),
            reader.IsDBNull(2) ? null : reader.GetGuid(2),
            reader.IsDBNull(3) ? null : reader.GetGuid(3));
    }

    private static async Task<PasswordResetFinalizeLookupResult> QueryLookupAsync(NpgsqlConnection connection, string sql, params (string Name, object? Value)[] parameters)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        AddParameters(command, parameters);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync();
        (await reader.ReadAsync()).ShouldBeTrue();

        return new PasswordResetFinalizeLookupResult(
            reader.GetBoolean(0),
            reader.GetString(1),
            reader.IsDBNull(3) ? null : reader.GetGuid(3),
            reader.IsDBNull(6) ? null : reader.GetString(6));
    }

    private static async Task<PasswordResetFailedAttemptResult> QueryFailedAttemptAsync(NpgsqlConnection connection, string sql, params (string Name, object? Value)[] parameters)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        AddParameters(command, parameters);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync();
        (await reader.ReadAsync()).ShouldBeTrue();

        return new PasswordResetFailedAttemptResult(
            reader.GetBoolean(0),
            reader.GetString(1),
            reader.IsDBNull(3) ? null : reader.GetInt32(3),
            reader.IsDBNull(5) ? null : reader.GetFieldValue<DateTimeOffset>(5));
    }

    private static async Task<PasswordResetCancelResult> QueryCancelAsync(NpgsqlConnection connection, string sql, params (string Name, object? Value)[] parameters)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        AddParameters(command, parameters);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync();
        (await reader.ReadAsync()).ShouldBeTrue();

        return new PasswordResetCancelResult(
            reader.GetBoolean(0),
            reader.GetString(1),
            reader.IsDBNull(2) ? null : reader.GetGuid(2),
            reader.IsDBNull(3) ? null : reader.GetFieldValue<DateTimeOffset>(3));
    }

    private static async Task<PasswordResetPromoteResult> QueryPromoteAsync(NpgsqlConnection connection, string sql, params (string Name, object? Value)[] parameters)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        AddParameters(command, parameters);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync();
        (await reader.ReadAsync()).ShouldBeTrue();

        return new PasswordResetPromoteResult(
            reader.GetBoolean(0),
            reader.GetString(1),
            reader.IsDBNull(2) ? null : reader.GetGuid(2),
            reader.IsDBNull(3) ? null : reader.GetGuid(3),
            reader.IsDBNull(4) ? null : reader.GetFieldValue<DateTimeOffset>(4));
    }


    private static async Task<PasswordResetRateLimitResult> QueryRateLimitAsync(NpgsqlConnection connection, string sql, params (string Name, object? Value)[] parameters)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        AddParameters(command, parameters);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync();
        (await reader.ReadAsync()).ShouldBeTrue();

        return new PasswordResetRateLimitResult(
            reader.GetBoolean(0),
            reader.GetString(1),
            reader.IsDBNull(2) ? null : reader.GetInt32(2),
            reader.IsDBNull(3) ? null : reader.GetFieldValue<DateTimeOffset>(3),
            reader.IsDBNull(4) ? null : reader.GetInt32(4));
    }

    private static async Task<PasswordResetTotpEnrollmentResult> QueryTotpEnrollmentAsync(NpgsqlConnection connection, string sql, params (string Name, object? Value)[] parameters)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        AddParameters(command, parameters);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync();
        if (!await reader.ReadAsync())
        {
            return PasswordResetTotpEnrollmentResult.Missing;
        }

        return new PasswordResetTotpEnrollmentResult(
            true,
            reader.GetGuid(0),
            reader.GetInt64(1),
            reader.GetInt16(2),
            reader.IsDBNull(7) ? null : reader.GetInt64(7),
            reader.GetGuid(9));
    }

    private static async Task<PasswordResetTotpStepResult> QueryTotpStepAsync(NpgsqlConnection connection, string sql, params (string Name, object? Value)[] parameters)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        AddParameters(command, parameters);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync();
        (await reader.ReadAsync()).ShouldBeTrue();

        return new PasswordResetTotpStepResult(
            reader.GetBoolean(0),
            reader.GetString(1));
    }

    private static void AddParameters(NpgsqlCommand command, params (string Name, object? Value)[] parameters)
    {
        foreach ((string name, object? value) in parameters)
        {
            command.Parameters.AddWithValue(name, value ?? DBNull.Value);
        }
    }

    private static string BaselinePath()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);

        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "treehammock.sln")))
        {
            directory = directory.Parent;
        }

        directory.ShouldNotBeNull("The test could not locate the project root containing treehammock.sln.");
        return Path.Combine(directory.FullName, "Rigging", "Database", "Baseline", "000_treehammock_canonical_database.sql");
    }

    private sealed record PasswordResetCreateResult(bool Result, string Code, Guid? PasswordResetRequestId, Guid? AccountId);
    private sealed record PasswordResetFinalizeLookupResult(bool Result, string Code, Guid? AccountId, string? KeyCodeHash);
    private sealed record PasswordResetFailedAttemptResult(bool Result, string Code, int? AttemptCount, DateTimeOffset? CancelledAt);
    private sealed record PasswordResetCancelResult(bool Result, string Code, Guid? AccountId, DateTimeOffset? CancelledAt);
    private sealed record PasswordResetPromoteResult(bool Result, string Code, Guid? AccountId, Guid? AccountSecurityStamp, DateTimeOffset? ConsumedAt);
    private sealed record PasswordResetRateLimitResult(bool Result, string Code, int? RequestCount, DateTimeOffset? BlockedUntil, int? RetryAfterSeconds);
    private sealed record PasswordResetTotpEnrollmentResult(bool Found, Guid? AccountId, long? TwoFactorIndex, short? Method, long? LastUsedStep, Guid? EnrollmentId)
    {
        public static PasswordResetTotpEnrollmentResult Missing { get; } = new(false, null, null, null, null, null);
    }

    private sealed record PasswordResetTotpStepResult(bool Result, string Code);
}
