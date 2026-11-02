using Npgsql;
using treehammock.Tests.SqlContracts.Support;
using Shouldly;

using treehammock.Rigging.Authorization;
using treehammock.Rigging.Security;

namespace treehammock.Tests.Integration.Database;

[Trait("Suite", "SqlContracts")]
public class BooleanProcedureContractTests
{
    private async Task<NpgsqlConnection> OpenDeferredSqlContractConnectionAsync()
    {
        if (!DeferredSqlProcedureContractSettings.ShouldRun())
        {
            throw new InvalidOperationException(DeferredSqlProcedureContractSettings.SkipReason);
        }

        string connectionString = DeferredSqlProcedureContractSettings.ConnectionString!;

        var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        return connection;
    }

    [Fact]
    public async Task Deferred_sql_procedure_contract_returns_status_rows_for_auth_and_session_surface()
    {
        await using NpgsqlConnection connection = await OpenDeferredSqlContractConnectionAsync();

        string schema = "contract_" + Guid.NewGuid().ToString("N");

        try
        {
            await ExecuteAsync(connection, $"create schema {schema};");
            await ExecuteAsync(connection, $"set search_path to {schema};");
            await ExecuteAsync(connection, File.ReadAllText(BaselinePath()));
            await Cor17EmailSql.Install(connection);
            await Cor18DeleteSql.Install(connection);

            Guid accountId = Guid.NewGuid();
            byte[] hashedPassword = Enumerable.Repeat((byte)1, 128).ToArray();
            byte[] saltOne = Enumerable.Repeat((byte)2, 64).ToArray();
            byte[] siv = Enumerable.Repeat((byte)3, 32).ToArray();
            byte[] nonce = Enumerable.Repeat((byte)4, 16).ToArray();
            byte[] oldRefreshToken = Enumerable.Repeat((byte)5, 64).ToArray();
            byte[] newRefreshToken = Enumerable.Repeat((byte)6, 64).ToArray();
            byte[] refreshedRefreshToken = Enumerable.Repeat((byte)6, 64).ToArray();

            await ExecuteAsync(
                connection,
                """
                insert into accounts(
                    account_id, email_address, username, hashed_password, web_key, salt_one, siv, nonce,
                    login_failures, verify_status, features, two_factor_access_token, two_factor_auth_method, two_auth_usage, cut_off)
                values (
                    @accountId, 'reader@example.com', 'reader', @hashedPassword, 'web-key-' || gen_random_uuid()::text, @saltOne, @siv, @nonce,
                    3, 1, 0, 'pending-old', 0, 0, now() + interval '45 minutes');
                """,
                ("accountId", accountId),
                ("hashedPassword", hashedPassword),
                ("saltOne", saltOne),
                ("siv", siv),
                ("nonce", nonce));

            Guid accountSecurityStamp = await QueryGuidAsync(connection, "select security_stamp from accounts where account_id = @accountId;", ("accountId", accountId));

            await ExecuteAsync(
                connection,
                """
                insert into two_factor_authentications(
                    two_factor_index, account_id, method, verified, priority)
                values (1, @accountId, 1, true, 10);
                """,
                ("accountId", accountId));

            AccountViewContractResult viewResult = await QueryAccountViewAsync(
                connection,
                "select * from view_account(@accountId, @accountSecurityStamp);",
                ("accountId", accountId),
                ("accountSecurityStamp", accountSecurityStamp));
            viewResult.Result.ShouldBeTrue();
            viewResult.Code.ShouldBe("ACCOUNT_VIEW_SUCCEEDED");
            viewResult.EmailAddress.ShouldBe("reader@example.com");
            viewResult.Username.ShouldBe("reader");
            viewResult.TwoFactorEnabled.ShouldBeTrue();
            viewResult.TwoFactorConfiguration.ShouldBe((short)2);
            viewResult.TwoFactorMethods.ShouldBe(new short[] { 1 });

            AccountViewContractResult staleViewResult = await QueryAccountViewAsync(
                connection,
                "select * from view_account(@accountId, @accountSecurityStamp);",
                ("accountId", accountId),
                ("accountSecurityStamp", Guid.NewGuid()));
            staleViewResult.Result.ShouldBeFalse();
            staleViewResult.Code.ShouldBe("ACCOUNT_SECURITY_STAMP_MISMATCH");
            staleViewResult.EmailAddress.ShouldBeNull();

            AccountViewContractResult missingViewResult = await QueryAccountViewAsync(
                connection,
                "select * from view_account(@accountId, @accountSecurityStamp);",
                ("accountId", Guid.NewGuid()),
                ("accountSecurityStamp", accountSecurityStamp));
            missingViewResult.Result.ShouldBeFalse();
            missingViewResult.Code.ShouldBe("ACCOUNT_NOT_FOUND");
            missingViewResult.EmailAddress.ShouldBeNull();

            await ExecuteAsync(
                connection,
                """
                insert into sessions(
                    access_token_hash, account_id, refresh_token, refreshes, refresh_limit, created_on, session_lifespan, access_expiration, session_expiration, features, account_security_stamp)
                values (
                    'old-active-hash', @accountId, @oldRefreshToken, 0, 5, now() - interval '30 minutes', interval '7 days', now() + interval '10 minutes', now() + interval '1 hour', 0, @accountSecurityStamp);
                """,
                ("accountId", accountId),
                ("oldRefreshToken", oldRefreshToken),
                ("accountSecurityStamp", accountSecurityStamp));

            (await QueryStringAsync(
                connection,
                "select active_access_token_hash from check_account_emailaddress_creds(@emailAddress);",
                ("emailAddress", "reader@example.com"))).ShouldBe("old-active-hash");

            DateTimeOffset credentialCutOff = await QueryDateTimeOffsetAsync(
                connection,
                "select cut_off from check_account_emailaddress_creds(@emailAddress);",
                ("emailAddress", "reader@example.com"));
            credentialCutOff.ShouldBeGreaterThan(DateTimeOffset.UtcNow);

            (await QueryGuidAsync(
                connection,
                "select account_id from get_session(@accessTokenHash);",
                ("accessTokenHash", "old-active-hash"))).ShouldBe(accountId);

            Guid oldActiveSecurityStamp = await QueryGuidAsync(
                connection,
                "select security_stamp from get_session(@accessTokenHash);",
                ("accessTokenHash", "old-active-hash"));
            oldActiveSecurityStamp.ShouldNotBe(Guid.Empty);

            await ExecuteAsync(
                connection,
                """
                insert into sessions(
                    access_token_hash, account_id, refresh_token, refreshes, refresh_limit, created_on, session_lifespan, access_expiration, session_expiration, features, account_security_stamp)
                values (
                    'direct-default-stamp-hash', @accountId, @oldRefreshToken, 0, 5, now() - interval '20 minutes', interval '7 days', now() + interval '9 minutes', now() + interval '50 minutes', 0, @accountSecurityStamp);
                """,
                ("accountId", accountId),
                ("oldRefreshToken", oldRefreshToken),
                ("accountSecurityStamp", accountSecurityStamp));

            Guid directDefaultSecurityStamp = await QueryGuidAsync(
                connection,
                "select security_stamp from get_session(@accessTokenHash);",
                ("accessTokenHash", "direct-default-stamp-hash"));
            directDefaultSecurityStamp.ShouldNotBe(Guid.Empty);
            directDefaultSecurityStamp.ShouldNotBe(oldActiveSecurityStamp);

            (short directDefaultTrustStatus, string directDefaultTrustCode) = await QueryShortStatusAsync(
                connection,
                "select status, code from validate_cached_session_trust(@accessTokenHash, @accountId, @securityStamp, @accountSecurityStamp);",
                ("accessTokenHash", "direct-default-stamp-hash"),
                ("accountId", accountId),
                ("securityStamp", directDefaultSecurityStamp),
                ("accountSecurityStamp", accountSecurityStamp));
            directDefaultTrustStatus.ShouldBe((short)1);
            directDefaultTrustCode.ShouldBe("VALID");

            (short directDefaultStaleTrustStatus, string directDefaultStaleTrustCode) = await QueryShortStatusAsync(
                connection,
                "select status, code from validate_cached_session_trust(@accessTokenHash, @accountId, @securityStamp, @accountSecurityStamp);",
                ("accessTokenHash", "direct-default-stamp-hash"),
                ("accountId", accountId),
                ("securityStamp", Guid.NewGuid()),
                ("accountSecurityStamp", accountSecurityStamp));
            directDefaultStaleTrustStatus.ShouldBe((short)4);
            directDefaultStaleTrustCode.ShouldBe("SECURITY_STAMP_MISMATCH");

            Guid stampBumpAccountId = Guid.NewGuid();
            await ExecuteAsync(
                connection,
                """
                insert into accounts(
                    account_id, email_address, username, hashed_password, web_key, salt_one, siv, nonce,
                    login_failures, verify_status, features, two_factor_auth_method)
                values (
                    @accountId, 'stamp-bump@example.com', 'stamp-bump-reader', @hashedPassword, 'stamp-bump-web-key', @saltOne, @siv, @nonce,
                    0, 1, 0, 0);
                """,
                ("accountId", stampBumpAccountId),
                ("hashedPassword", hashedPassword),
                ("saltOne", saltOne),
                ("siv", siv),
                ("nonce", nonce));

            Guid stampBumpOriginalAccountSecurityStamp = await QueryGuidAsync(connection, "select security_stamp from accounts where account_id = @accountId;", ("accountId", stampBumpAccountId));

            await ExecuteAsync(
                connection,
                """
                insert into sessions(
                    access_token_hash, account_id, refresh_token, refreshes, refresh_limit, created_on, session_lifespan, access_expiration, session_expiration, features, account_security_stamp)
                values (
                    'stamp-bump-hash', @accountId, @oldRefreshToken, 0, 5, now(), interval '7 days', now() + interval '10 minutes', now() + interval '1 hour', 0, @accountSecurityStamp);
                """,
                ("accountId", stampBumpAccountId),
                ("oldRefreshToken", oldRefreshToken),
                ("accountSecurityStamp", stampBumpOriginalAccountSecurityStamp));

            Guid stampBumpSessionSecurityStamp = await QueryGuidAsync(
                connection,
                "select security_stamp from get_session(@accessTokenHash);",
                ("accessTokenHash", "stamp-bump-hash"));

            (short stampBumpInitialTrustStatus, string stampBumpInitialTrustCode) = await QueryShortStatusAsync(
                connection,
                "select status, code from validate_cached_session_trust(@accessTokenHash, @accountId, @securityStamp, @accountSecurityStamp);",
                ("accessTokenHash", "stamp-bump-hash"),
                ("accountId", stampBumpAccountId),
                ("securityStamp", stampBumpSessionSecurityStamp),
                ("accountSecurityStamp", stampBumpOriginalAccountSecurityStamp));
            stampBumpInitialTrustStatus.ShouldBe((short)1);
            stampBumpInitialTrustCode.ShouldBe("VALID");

            (bool stampRotated, string stampRotatedCode) = await QueryBoolStatusAsync(
                connection,
                "select result, code from rotate_account_security_stamp(@accountId);",
                ("accountId", stampBumpAccountId));
            stampRotated.ShouldBeTrue();
            stampRotatedCode.ShouldBe("ROTATED");

            Guid stampBumpCurrentAccountSecurityStamp = await QueryGuidAsync(connection, "select security_stamp from accounts where account_id = @accountId;", ("accountId", stampBumpAccountId));
            stampBumpCurrentAccountSecurityStamp.ShouldNotBe(stampBumpOriginalAccountSecurityStamp);

            (short stampBumpStaleTrustStatus, string stampBumpStaleTrustCode) = await QueryShortStatusAsync(
                connection,
                "select status, code from validate_cached_session_trust(@accessTokenHash, @accountId, @securityStamp, @accountSecurityStamp);",
                ("accessTokenHash", "stamp-bump-hash"),
                ("accountId", stampBumpAccountId),
                ("securityStamp", stampBumpSessionSecurityStamp),
                ("accountSecurityStamp", stampBumpOriginalAccountSecurityStamp));
            stampBumpStaleTrustStatus.ShouldBe((short)6);
            stampBumpStaleTrustCode.ShouldBe("ACCOUNT_SECURITY_STAMP_MISMATCH");

            Guid cutoffAccountId = Guid.NewGuid();
            await ExecuteAsync(
                connection,
                """
                insert into accounts(
                    account_id, email_address, username, hashed_password, web_key, salt_one, siv, nonce,
                    login_failures, verify_status, features, two_factor_auth_method)
                values (
                    @accountId, 'cutoff@example.com', 'cutoff-reader', @hashedPassword, 'cutoff-web-key', @saltOne, @siv, @nonce,
                    0, 1, 0, 0);
                """,
                ("accountId", cutoffAccountId),
                ("hashedPassword", hashedPassword),
                ("saltOne", saltOne),
                ("siv", siv),
                ("nonce", nonce));

            Guid cutoffAccountSecurityStamp = await QueryGuidAsync(connection, "select security_stamp from accounts where account_id = @accountId;", ("accountId", cutoffAccountId));

            await ExecuteAsync(
                connection,
                """
                insert into sessions(
                    access_token_hash, account_id, refresh_token, refreshes, refresh_limit, created_on, session_lifespan, access_expiration, session_expiration, cut_off, features, account_security_stamp)
                values (
                    'account-cutoff-hash', @accountId, @oldRefreshToken, 0, 5, now(), interval '7 days', now() + interval '10 minutes', now() + interval '1 hour', now() + interval '30 minutes', 0, @accountSecurityStamp);
                """,
                ("accountId", cutoffAccountId),
                ("oldRefreshToken", oldRefreshToken),
                ("accountSecurityStamp", cutoffAccountSecurityStamp));

            Guid cutoffSessionSecurityStamp = await QueryGuidAsync(
                connection,
                "select security_stamp from get_session(@accessTokenHash);",
                ("accessTokenHash", "account-cutoff-hash"));

            (short cutoffInitialTrustStatus, string cutoffInitialTrustCode) = await QueryShortStatusAsync(
                connection,
                "select status, code from validate_cached_session_trust(@accessTokenHash, @accountId, @securityStamp, @accountSecurityStamp);",
                ("accessTokenHash", "account-cutoff-hash"),
                ("accountId", cutoffAccountId),
                ("securityStamp", cutoffSessionSecurityStamp),
                ("accountSecurityStamp", cutoffAccountSecurityStamp));
            cutoffInitialTrustStatus.ShouldBe((short)1);
            cutoffInitialTrustCode.ShouldBe("VALID");

            await ExecuteAsync(
                connection,
                "update accounts set cut_off = now() - interval '1 minute' where account_id = @accountId;",
                ("accountId", cutoffAccountId));

            var cutoffTrustState = await QueryTrustStateAsync(
                connection,
                "select status, code, access_expiration, session_expiration, cut_off, security_stamp, account_security_stamp from validate_cached_session_trust(@accessTokenHash, @accountId, @securityStamp, @accountSecurityStamp);",
                ("accessTokenHash", "account-cutoff-hash"),
                ("accountId", cutoffAccountId),
                ("securityStamp", cutoffSessionSecurityStamp),
                ("accountSecurityStamp", cutoffAccountSecurityStamp));
            cutoffTrustState.Status.ShouldBe((short)5);
            cutoffTrustState.Code.ShouldBe("SESSION_EXPIRED");
            cutoffTrustState.CutOff.ShouldNotBeNull();
            cutoffTrustState.CutOff.Value.ShouldBeLessThan(DateTimeOffset.UtcNow.AddSeconds(5));

            DateTimeOffset hydratedCutOff = await QueryDateTimeOffsetAsync(
                connection,
                "select cut_off from get_session(@accessTokenHash);",
                ("accessTokenHash", "account-cutoff-hash"));
            hydratedCutOff.ShouldBeLessThan(DateTimeOffset.UtcNow.AddSeconds(5));

            (bool missingStampRotation, string missingStampRotationCode) = await QueryBoolStatusAsync(
                connection,
                "select result, code from rotate_account_security_stamp(@accountId);",
                ("accountId", Guid.NewGuid()));
            missingStampRotation.ShouldBeFalse();
            missingStampRotationCode.ShouldBe("ACCOUNT_NOT_FOUND");

            Guid setSessionAccountId = Guid.NewGuid();
            await ExecuteAsync(
                connection,
                """
                insert into accounts(
                    account_id, email_address, username, hashed_password, web_key, salt_one, siv, nonce,
                    login_failures, verify_status, features, two_factor_auth_method)
                values (
                    @accountId, 'set-session@example.com', 'set-session-reader', @hashedPassword, 'set-session-web-key', @saltOne, @siv, @nonce,
                    0, 1, 0, 0);
                """,
                ("accountId", setSessionAccountId),
                ("hashedPassword", hashedPassword),
                ("saltOne", saltOne),
                ("siv", siv),
                ("nonce", nonce));

            Guid setSessionAccountSecurityStamp = await QueryGuidAsync(connection, "select security_stamp from accounts where account_id = @accountId;", ("accountId", setSessionAccountId));

            (short setSessionResult, string setSessionCode) = await QueryShortStatusAsync(
                connection,
                """
                select result, code from set_session(
                    @accessTokenHash, @accountId, @refreshToken, @refreshes, @limit,
                    @createdOn, @sessionLifespan, @accessExpiration, @sessionExpiration, @cutOff, @features, @securityStamp, @accountSecurityStamp);
                """,
                ("accessTokenHash", "set-session-hash"),
                ("accountId", setSessionAccountId),
                ("refreshToken", oldRefreshToken),
                ("refreshes", (short)0),
                ("limit", (short)5),
                ("createdOn", DateTimeOffset.UtcNow),
                ("sessionLifespan", TimeSpan.FromDays(7)),
                ("accessExpiration", DateTimeOffset.UtcNow.AddMinutes(10)),
                ("sessionExpiration", DateTimeOffset.UtcNow.AddDays(7)),
                ("cutOff", DateTimeOffset.UtcNow.AddDays(7)),
                ("features", (short)0),
                ("securityStamp", Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")),
                ("accountSecurityStamp", setSessionAccountSecurityStamp));

            setSessionResult.ShouldBe((short)1);
            setSessionCode.ShouldBe("SUCCESSFUL");

            (short trustStatus, string trustCode) = await QueryShortStatusAsync(
                connection,
                "select status, code from validate_cached_session_trust(@accessTokenHash, @accountId, @securityStamp, @accountSecurityStamp);",
                ("accessTokenHash", "set-session-hash"),
                ("accountId", setSessionAccountId),
                ("securityStamp", Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")),
                ("accountSecurityStamp", setSessionAccountSecurityStamp));
            trustStatus.ShouldBe((short)1);
            trustCode.ShouldBe("VALID");

            var trustState = await QueryTrustStateAsync(
                connection,
                "select status, code, access_expiration, session_expiration, cut_off, security_stamp, account_security_stamp from validate_cached_session_trust(@accessTokenHash, @accountId, @securityStamp, @accountSecurityStamp);",
                ("accessTokenHash", "set-session-hash"),
                ("accountId", setSessionAccountId),
                ("securityStamp", Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")),
                ("accountSecurityStamp", setSessionAccountSecurityStamp));
            trustState.Status.ShouldBe((short)1);
            trustState.Code.ShouldBe("VALID");
            trustState.AccessExpiration.ShouldNotBeNull();
            trustState.SessionExpiration.ShouldNotBeNull();
            trustState.CutOff.ShouldNotBeNull();
            trustState.SecurityStamp.ShouldBe(Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"));
            trustState.AccountSecurityStamp.ShouldBe(setSessionAccountSecurityStamp);

            (short staleTrustStatus, string staleTrustCode) = await QueryShortStatusAsync(
                connection,
                "select status, code from validate_cached_session_trust(@accessTokenHash, @accountId, @securityStamp, @accountSecurityStamp);",
                ("accessTokenHash", "set-session-hash"),
                ("accountId", setSessionAccountId),
                ("securityStamp", Guid.Parse("99999999-9999-9999-9999-999999999999")),
                ("accountSecurityStamp", setSessionAccountSecurityStamp));
            staleTrustStatus.ShouldBe((short)4);
            staleTrustCode.ShouldBe("SECURITY_STAMP_MISMATCH");

            (short duplicateSetResult, string duplicateSetCode) = await QueryShortStatusAsync(
                connection,
                """
                select result, code from set_session(
                    @accessTokenHash, @accountId, @refreshToken, @refreshes, @limit,
                    @createdOn, @sessionLifespan, @accessExpiration, @sessionExpiration, @cutOff, @features, @securityStamp, @accountSecurityStamp);
                """,
                ("accessTokenHash", "set-session-hash"),
                ("accountId", setSessionAccountId),
                ("refreshToken", oldRefreshToken),
                ("refreshes", (short)0),
                ("limit", (short)5),
                ("createdOn", DateTimeOffset.UtcNow),
                ("sessionLifespan", TimeSpan.FromDays(7)),
                ("accessExpiration", DateTimeOffset.UtcNow.AddMinutes(10)),
                ("sessionExpiration", DateTimeOffset.UtcNow.AddDays(7)),
                ("cutOff", DateTimeOffset.UtcNow.AddDays(7)),
                ("features", (short)0),
                ("securityStamp", Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")),
                ("accountSecurityStamp", setSessionAccountSecurityStamp));

            duplicateSetResult.ShouldBe((short)5000);
            duplicateSetCode.ShouldBe("NEW_SESSION_CONFLICT");

            DateTimeOffset setSessionAccessExpiration = await QueryDateTimeOffsetAsync(connection, "select access_expiration from get_session(@accessTokenHash);", ("accessTokenHash", "set-session-hash"));
            DateTimeOffset setSessionSessionExpiration = await QueryDateTimeOffsetAsync(connection, "select session_expiration from get_session(@accessTokenHash);", ("accessTokenHash", "set-session-hash"));
            setSessionAccessExpiration.ShouldBeLessThan(setSessionSessionExpiration);

            Guid singleSessionAccountId = Guid.NewGuid();
            await ExecuteAsync(
                connection,
                """
                insert into accounts(
                    account_id, email_address, username, hashed_password, web_key, salt_one, siv, nonce,
                    login_failures, verify_status, features, two_factor_auth_method)
                values (
                    @accountId, 'single-session@example.com', 'single-session-reader', @hashedPassword, 'single-session-web-key', @saltOne, @siv, @nonce,
                    0, 1, 0, 0);
                """,
                ("accountId", singleSessionAccountId),
                ("hashedPassword", hashedPassword),
                ("saltOne", saltOne),
                ("siv", siv),
                ("nonce", nonce));

            Guid singleSessionAccountSecurityStamp = await QueryGuidAsync(connection, "select security_stamp from accounts where account_id = @accountId;", ("accountId", singleSessionAccountId));

            (short firstSingleSessionResult, string firstSingleSessionCode) = await QueryShortStatusAsync(
                connection,
                """
                select result, code from set_session(
                    @accessTokenHash, @accountId, @refreshToken, @refreshes, @limit,
                    @createdOn, @sessionLifespan, @accessExpiration, @sessionExpiration, @cutOff, @features, @securityStamp, @accountSecurityStamp);
                """,
                ("accessTokenHash", "single-session-first"),
                ("accountId", singleSessionAccountId),
                ("refreshToken", oldRefreshToken),
                ("refreshes", (short)0),
                ("limit", (short)5),
                ("createdOn", DateTimeOffset.UtcNow),
                ("sessionLifespan", TimeSpan.FromDays(7)),
                ("accessExpiration", DateTimeOffset.UtcNow.AddMinutes(10)),
                ("sessionExpiration", DateTimeOffset.UtcNow.AddDays(7)),
                ("cutOff", DateTimeOffset.UtcNow.AddDays(7)),
                ("features", (short)0),
                ("securityStamp", Guid.Parse("11111111-1111-1111-1111-111111111111")),
                ("accountSecurityStamp", singleSessionAccountSecurityStamp));

            firstSingleSessionResult.ShouldBe((short)1);
            firstSingleSessionCode.ShouldBe("SUCCESSFUL");

            (short secondSingleSessionResult, string secondSingleSessionCode) = await QueryShortStatusAsync(
                connection,
                """
                select result, code from set_session(
                    @accessTokenHash, @accountId, @refreshToken, @refreshes, @limit,
                    @createdOn, @sessionLifespan, @accessExpiration, @sessionExpiration, @cutOff, @features, @securityStamp, @accountSecurityStamp);
                """,
                ("accessTokenHash", "single-session-second"),
                ("accountId", singleSessionAccountId),
                ("refreshToken", newRefreshToken),
                ("refreshes", (short)0),
                ("limit", (short)5),
                ("createdOn", DateTimeOffset.UtcNow.AddMinutes(1)),
                ("sessionLifespan", TimeSpan.FromDays(7)),
                ("accessExpiration", DateTimeOffset.UtcNow.AddMinutes(20)),
                ("sessionExpiration", DateTimeOffset.UtcNow.AddDays(7)),
                ("cutOff", DateTimeOffset.UtcNow.AddDays(7)),
                ("features", (short)0),
                ("securityStamp", Guid.Parse("22222222-2222-2222-2222-222222222222")),
                ("accountSecurityStamp", singleSessionAccountSecurityStamp));

            secondSingleSessionResult.ShouldBe((short)1);
            secondSingleSessionCode.ShouldBe("SUCCESSFUL");

            (short supersededTrustStatus, string supersededTrustCode) = await QueryShortStatusAsync(
                connection,
                "select status, code from validate_cached_session_trust(@accessTokenHash, @accountId, @securityStamp, @accountSecurityStamp);",
                ("accessTokenHash", "single-session-first"),
                ("accountId", singleSessionAccountId),
                ("securityStamp", Guid.Parse("11111111-1111-1111-1111-111111111111")),
                ("accountSecurityStamp", singleSessionAccountSecurityStamp));
            supersededTrustStatus.ShouldBe((short)5);
            supersededTrustCode.ShouldBe("SESSION_EXPIRED");

            (await QueryStringAsync(
                connection,
                "select active_access_token_hash from get_current_active_session_hash(@accountId);",
                ("accountId", singleSessionAccountId))).ShouldBe("single-session-second");

            Guid rotationAccountId = Guid.NewGuid();
            byte[] rotationOldRefreshToken = Enumerable.Repeat((byte)8, 64).ToArray();
            byte[] rotationNewRefreshToken = Enumerable.Repeat((byte)9, 64).ToArray();
            await ExecuteAsync(
                connection,
                """
                insert into accounts(
                    account_id, email_address, username, hashed_password, web_key, salt_one, siv, nonce,
                    login_failures, verify_status, features, two_factor_auth_method)
                values (
                    @accountId, 'rotation@example.com', 'rotation-reader', @hashedPassword, 'rotation-web-key', @saltOne, @siv, @nonce,
                    4, 1, 0, 0);
                """,
                ("accountId", rotationAccountId),
                ("hashedPassword", hashedPassword),
                ("saltOne", saltOne),
                ("siv", siv),
                ("nonce", nonce));

            Guid rotationAccountSecurityStamp = await QueryGuidAsync(connection, "select security_stamp from accounts where account_id = @accountId;", ("accountId", rotationAccountId));

            await ExecuteAsync(
                connection,
                """
                insert into sessions(
                    access_token_hash, account_id, refresh_token, refreshes, refresh_limit, created_on, session_lifespan, access_expiration, session_expiration, features, account_security_stamp)
                values (
                    'rotation-old-hash', @accountId, @oldRefreshToken, 0, 5, now() - interval '10 minutes', interval '7 days', now() + interval '10 minutes', now() + interval '1 hour', 0, @accountSecurityStamp);
                """,
                ("accountId", rotationAccountId),
                ("oldRefreshToken", rotationOldRefreshToken),
                ("accountSecurityStamp", rotationAccountSecurityStamp));

            (short mismatchStatus, string mismatchCode) = await QueryShortStatusAsync(
                connection,
                """
                select status, code from rotate_active_session(
                    @accountId, @expectedOldAccessTokenHash, @newAccessTokenHash, @refreshToken, @refreshes, @limit,
                    @createdOn, @sessionLifespan, @accessExpiration, @sessionExpiration, @cutOff, @features, @securityStamp, @accountSecurityStamp);
                """,
                ("accountId", rotationAccountId),
                ("expectedOldAccessTokenHash", "wrong-old-hash"),
                ("newAccessTokenHash", "rotation-should-not-insert"),
                ("refreshToken", rotationNewRefreshToken),
                ("refreshes", (short)1),
                ("limit", (short)5),
                ("createdOn", DateTimeOffset.UtcNow),
                ("sessionLifespan", TimeSpan.FromDays(7)),
                ("accessExpiration", DateTimeOffset.UtcNow.AddMinutes(10)),
                ("sessionExpiration", DateTimeOffset.UtcNow.AddDays(7)),
                ("cutOff", DateTimeOffset.UtcNow.AddDays(7)),
                ("features", (short)0),
                ("securityStamp", Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")),
                ("accountSecurityStamp", rotationAccountSecurityStamp));

            mismatchStatus.ShouldBe((short)2);
            mismatchCode.ShouldBe("OLD_SESSION_MISMATCH");

            (await QueryStringAsync(
                connection,
                "select active_access_token_hash from get_current_active_session_hash(@accountId);",
                ("accountId", rotationAccountId))).ShouldBe("rotation-old-hash");

            (short rotateStatus, string rotateCode) = await QueryShortStatusAsync(
                connection,
                """
                select status, code from rotate_active_session(
                    @accountId, @expectedOldAccessTokenHash, @newAccessTokenHash, @refreshToken, @refreshes, @limit,
                    @createdOn, @sessionLifespan, @accessExpiration, @sessionExpiration, @cutOff, @features, @securityStamp, @accountSecurityStamp);
                """,
                ("accountId", rotationAccountId),
                ("expectedOldAccessTokenHash", "rotation-old-hash"),
                ("newAccessTokenHash", "rotation-new-hash"),
                ("refreshToken", rotationNewRefreshToken),
                ("refreshes", (short)1),
                ("limit", (short)5),
                ("createdOn", DateTimeOffset.UtcNow),
                ("sessionLifespan", TimeSpan.FromDays(7)),
                ("accessExpiration", DateTimeOffset.UtcNow.AddMinutes(10)),
                ("sessionExpiration", DateTimeOffset.UtcNow.AddDays(7)),
                ("cutOff", DateTimeOffset.UtcNow.AddDays(7)),
                ("features", (short)0),
                ("securityStamp", Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")),
                ("accountSecurityStamp", rotationAccountSecurityStamp));

            rotateStatus.ShouldBe((short)1);
            rotateCode.ShouldBe("SUCCEEDED");

            (await QueryStringAsync(
                connection,
                "select active_access_token_hash from get_current_active_session_hash(@accountId);",
                ("accountId", rotationAccountId))).ShouldBe("rotation-new-hash");

            (await QueryStringAsync(
                connection,
                "select active_access_token_hash from check_account_emailaddress_creds(@emailAddress);",
                ("emailAddress", "rotation@example.com"))).ShouldBe("rotation-new-hash");

            (short doubleRefreshStatus, string doubleRefreshCode) = await QueryShortStatusAsync(
                connection,
                """
                select status, code from rotate_active_session(
                    @accountId, @expectedOldAccessTokenHash, @newAccessTokenHash, @refreshToken, @refreshes, @limit,
                    @createdOn, @sessionLifespan, @accessExpiration, @sessionExpiration, @cutOff, @features, @securityStamp, @accountSecurityStamp);
                """,
                ("accountId", rotationAccountId),
                ("expectedOldAccessTokenHash", "rotation-old-hash"),
                ("newAccessTokenHash", "rotation-double-refresh-hash"),
                ("refreshToken", rotationNewRefreshToken),
                ("refreshes", (short)2),
                ("limit", (short)5),
                ("createdOn", DateTimeOffset.UtcNow),
                ("sessionLifespan", TimeSpan.FromDays(7)),
                ("accessExpiration", DateTimeOffset.UtcNow.AddMinutes(10)),
                ("sessionExpiration", DateTimeOffset.UtcNow.AddDays(7)),
                ("cutOff", DateTimeOffset.UtcNow.AddDays(7)),
                ("features", (short)0),
                ("securityStamp", Guid.Parse("cccccccc-cccc-cccc-cccc-cccccccccccc")),
                ("accountSecurityStamp", rotationAccountSecurityStamp));

            doubleRefreshStatus.ShouldBe((short)2);
            doubleRefreshCode.ShouldBe("OLD_SESSION_MISMATCH");
            (await QueryStringAsync(
                connection,
                "select active_access_token_hash from get_current_active_session_hash(@accountId);",
                ("accountId", rotationAccountId))).ShouldBe("rotation-new-hash");
            (await QueryStringAsync(connection, "select access_token_hash from sessions where access_token_hash = 'rotation-double-refresh-hash';")).ShouldBeNull();

            (bool staleSuccessfulLogin, string staleSuccessfulLoginCode) = await QueryBoolStatusAsync(
                connection,
                "select result, code from successful_login(@accountId, @accountSecurityStamp);",
                ("accountId", accountId),
                ("accountSecurityStamp", Guid.NewGuid()));
            staleSuccessfulLogin.ShouldBeFalse();
            staleSuccessfulLoginCode.ShouldBe("LOGIN_ATTEMPT_VERSION_REQUIRED");

            (bool successfulLogin, string successfulLoginCode) = await QueryBoolStatusAsync(
                connection,
                "select result, code from successful_login(@accountId, @accountSecurityStamp);",
                ("accountId", accountId),
                ("accountSecurityStamp", accountSecurityStamp));
            successfulLogin.ShouldBeFalse();
            successfulLoginCode.ShouldBe("LOGIN_ATTEMPT_VERSION_REQUIRED");

            (await QueryBoolAsync(
                connection,
                "select result from successful_login(@accountId, @accountSecurityStamp);",
                ("accountId", Guid.NewGuid()),
                ("accountSecurityStamp", Guid.NewGuid()))).ShouldBeFalse();

            (bool loginFailuresSet, string loginFailuresCode) = await QueryBoolStatusAsync(
                connection,
                "select result, code from set_account_login_failures(@accountGuid, @failures);",
                ("accountGuid", accountId),
                ("failures", (short)2));
            loginFailuresSet.ShouldBeFalse();
            loginFailuresCode.ShouldBe("LOGIN_ATTEMPT_VERSION_REQUIRED");

            (bool lockedAccount, string lockoutCode) = await QueryBoolStatusAsync(
                connection,
                "select result, code from set_account_lockout(@accountGuid, @expiration);",
                ("accountGuid", accountId),
                ("expiration", TimeSpan.FromHours(6)));
            lockedAccount.ShouldBeFalse();
            lockoutCode.ShouldBe("LOGIN_ATTEMPT_VERSION_REQUIRED");

            (bool unlockedAccount, string unlockCode) = await QueryBoolStatusAsync(
                connection,
                "select result, code from remove_account_lockout(@accountGuid);",
                ("accountGuid", accountId));
            unlockedAccount.ShouldBeFalse();
            unlockCode.ShouldBe("LOGIN_ATTEMPT_VERSION_REQUIRED");

            await ExecuteAsync(
                connection,
                """
                insert into sessions(
                    access_token_hash, account_id, refresh_token, refreshes, refresh_limit, created_on, session_lifespan, access_expiration, session_expiration, features, account_security_stamp)
                values (
                    'refreshed-active-hash', @accountId, @refreshedRefreshToken, 1, 5, now(), interval '7 days', now() + interval '10 minutes', now() + interval '2 hours', 0, @accountSecurityStamp);
                """,
                ("accountId", accountId),
                ("refreshedRefreshToken", refreshedRefreshToken),
                ("accountSecurityStamp", accountSecurityStamp));

            (await QueryStringAsync(
                connection,
                "select active_access_token_hash from check_account_emailaddress_creds(@emailAddress);",
                ("emailAddress", "reader@example.com"))).ShouldBe("refreshed-active-hash");

            (bool revokeOld, string revokeOldCode) = await QueryBoolStatusAsync(connection, "select result, code from revoke_session(@accessTokenHash);", ("accessTokenHash", "old-active-hash"));
            revokeOld.ShouldBeTrue();
            revokeOldCode.ShouldBe("EXPIRED");

            (await QueryStringAsync(
                connection,
                "select active_access_token_hash from check_account_username_creds(@username);",
                ("username", "reader"))).ShouldBe("refreshed-active-hash");

            await ExecuteAsync(
                connection,
                """
                insert into sessions(
                    access_token_hash, account_id, refresh_token, refreshes, refresh_limit, created_on, session_lifespan, access_expiration, session_expiration, features, account_security_stamp)
                values (
                    'second-active-hash', @accountId, @refreshedRefreshToken, 0, 5, now() + interval '1 minute', interval '7 days', now() + interval '10 minutes', now() + interval '3 hours', 0, @accountSecurityStamp);
                """,
                ("accountId", accountId),
                ("refreshedRefreshToken", refreshedRefreshToken),
                ("accountSecurityStamp", accountSecurityStamp));

            (await QueryStringAsync(
                connection,
                "select active_access_token_hash from get_current_active_session_hash(@accountId);",
                ("accountId", accountId))).ShouldBe("second-active-hash");

            Guid refreshedActiveSecurityStamp = await QueryGuidAsync(
                connection,
                "select security_stamp from get_session(@accessTokenHash);",
                ("accessTokenHash", "refreshed-active-hash"));

            await ExecuteAsync(
                connection,
                "insert into sessions(access_token_hash, account_id, access_expiration, session_expiration, account_security_stamp) values ('token-a', @accountId, now() + interval '10 minutes', now() + interval '1 hour', @accountSecurityStamp);",
                ("accountId", accountId),
                ("accountSecurityStamp", accountSecurityStamp));

            (bool expiredToken, string expiredCode) = await QueryBoolStatusAsync(
                connection,
                "select result, code from expire_session(@accessTokenHash, @expiration);",
                ("accessTokenHash", "token-a"),
                ("expiration", DateTimeOffset.UtcNow));
            expiredToken.ShouldBeTrue();
            expiredCode.ShouldBe("EXPIRED");

            Guid expiredTokenSecurityStamp = await QueryGuidAsync(
                connection,
                "select security_stamp from get_session(@accessTokenHash);",
                ("accessTokenHash", "token-a"));
            (short expiredTrustStatus, string expiredTrustCode) = await QueryShortStatusAsync(
                connection,
                "select status, code from validate_cached_session_trust(@accessTokenHash, @accountId, @securityStamp, @accountSecurityStamp);",
                ("accessTokenHash", "token-a"),
                ("accountId", accountId),
                ("securityStamp", expiredTokenSecurityStamp),
                ("accountSecurityStamp", accountSecurityStamp));
            expiredTrustStatus.ShouldBe((short)5);
            expiredTrustCode.ShouldBe("SESSION_EXPIRED");

            (bool expiredMissing, string expiredMissingCode) = await QueryBoolStatusAsync(
                connection,
                "select result, code from expire_session(@accessTokenHash, @expiration);",
                ("accessTokenHash", "missing-token"),
                ("expiration", DateTimeOffset.UtcNow));
            expiredMissing.ShouldBeFalse();
            expiredMissingCode.ShouldBe("SESSION_NOT_FOUND");

            (bool revokedToken, string revokedCode) = await QueryBoolStatusAsync(connection, "select result, code from revoke_session(@accessTokenHash);", ("accessTokenHash", "token-a"));
            revokedToken.ShouldBeTrue();
            revokedCode.ShouldBe("EXPIRED");

            (bool revokedMissing, string revokedMissingCode) = await QueryBoolStatusAsync(connection, "select result, code from revoke_session(@accessTokenHash);", ("accessTokenHash", "token-a"));
            revokedMissing.ShouldBeTrue();
            revokedMissingCode.ShouldBe("EXPIRED");

            (bool usernameChanged, string usernameChangedCode) = await QueryBoolStatusAsync(
                connection,
                "select result, code from edit_account_username(@accountId, @accountSecurityStamp, @username);",
                ("accountId", accountId),
                ("accountSecurityStamp", accountSecurityStamp),
                ("username", "reader_renamed"));
            usernameChanged.ShouldBeTrue();
            usernameChangedCode.ShouldBe("ACCOUNT_ADJUST_SUCCEEDED");

            (bool staleUsernameChange, string staleUsernameChangeCode) = await QueryBoolStatusAsync(
                connection,
                "select result, code from edit_account_username(@accountId, @accountSecurityStamp, @username);",
                ("accountId", accountId),
                ("accountSecurityStamp", Guid.NewGuid()),
                ("username", "reader_again"));
            staleUsernameChange.ShouldBeFalse();
            staleUsernameChangeCode.ShouldBe("ACCOUNT_SECURITY_STAMP_MISMATCH");

            (bool expiredEmailChangeRequest, string expiredEmailChangeRequestCode) = await QueryBoolStatusAsync(
                connection,
                "select result, code from cor17_fixture_request_email(@accountId, @accountSecurityStamp, @newEmailAddress, @verifyKeyHash, @expiration);",
                ("accountId", accountId),
                ("accountSecurityStamp", accountSecurityStamp),
                ("newEmailAddress", "expired-new-reader@example.com"),
                ("verifyKeyHash", "expired-verify-hash"),
                ("expiration", DateTimeOffset.UtcNow.AddHours(-1)));
            expiredEmailChangeRequest.ShouldBeFalse();
            expiredEmailChangeRequestCode.ShouldBe("ACCOUNT_ADJUST_FAILED");

            (bool emailChangePending, string emailChangePendingCode) = await QueryBoolStatusAsync(
                connection,
                "select result, code from cor17_fixture_request_email(@accountId, @accountSecurityStamp, @newEmailAddress, @verifyKeyHash, @expiration);",
                ("accountId", accountId),
                ("accountSecurityStamp", accountSecurityStamp),
                ("newEmailAddress", "new-reader@example.com"),
                ("verifyKeyHash", "verify-hash"),
                ("expiration", DateTimeOffset.UtcNow.AddHours(1)));
            emailChangePending.ShouldBeTrue();
            emailChangePendingCode.ShouldBe("ACCOUNT_ADJUST_EMAIL_VERIFICATION_PENDING");

            (bool duplicateEmailChange, string duplicateEmailChangeCode) = await QueryBoolStatusAsync(
                connection,
                "select result, code from cor17_fixture_request_email(@accountId, @accountSecurityStamp, @newEmailAddress, @verifyKeyHash, @expiration);",
                ("accountId", accountId),
                ("accountSecurityStamp", accountSecurityStamp),
                ("newEmailAddress", "reader@example.com"),
                ("verifyKeyHash", "verify-hash-duplicate"),
                ("expiration", DateTimeOffset.UtcNow.AddHours(1)));
            duplicateEmailChange.ShouldBeFalse();
            duplicateEmailChangeCode.ShouldBe("ACCOUNT_ADJUST_DUPLICATE_EMAIL");

            Guid cancelledEmailAccountId = Guid.NewGuid();
            await ExecuteAsync(
                connection,
                """
                insert into accounts(
                    account_id, email_address, username, hashed_password, web_key, salt_one, siv, nonce,
                    login_failures, verify_status, features, two_factor_auth_method)
                values (
                    @accountId, 'cancel-email-change@example.com', 'cancel-email-change-reader', @hashedPassword, 'cancel-email-web-key', @saltOne, @siv, @nonce,
                    0, 1, 0, 0);
                """,
                ("accountId", cancelledEmailAccountId),
                ("hashedPassword", hashedPassword),
                ("saltOne", saltOne),
                ("siv", siv),
                ("nonce", nonce));

            Guid cancelledEmailAccountSecurityStamp = await QueryGuidAsync(connection, "select security_stamp from accounts where account_id = @accountId;", ("accountId", cancelledEmailAccountId));

            (bool cancelPending, string cancelPendingCode) = await QueryBoolStatusAsync(
                connection,
                "select result, code from cor17_fixture_request_email(@accountId, @accountSecurityStamp, @newEmailAddress, @verifyKeyHash, @expiration);",
                ("accountId", cancelledEmailAccountId),
                ("accountSecurityStamp", cancelledEmailAccountSecurityStamp),
                ("newEmailAddress", "cancelled-new-reader@example.com"),
                ("verifyKeyHash", "cancel-email-verify-hash"),
                ("expiration", DateTimeOffset.UtcNow.AddHours(1)));
            cancelPending.ShouldBeTrue();
            cancelPendingCode.ShouldBe("ACCOUNT_ADJUST_EMAIL_VERIFICATION_PENDING");

            (bool cancelEmailRequest, string cancelEmailRequestCode) = await QueryBoolStatusAsync(
                connection,
                "select result, code from cancel_account_email_change_request(@accountId, @accountSecurityStamp, @verifyKeyHash);",
                ("accountId", cancelledEmailAccountId),
                ("accountSecurityStamp", cancelledEmailAccountSecurityStamp),
                ("verifyKeyHash", "cancel-email-verify-hash"));
            cancelEmailRequest.ShouldBeTrue();
            cancelEmailRequestCode.ShouldBe("ACCOUNT_ADJUST_EMAIL_CHANGE_CANCELLED");

            (await QueryBoolAsync(
                connection,
                "select exists(select 1 from account_email_change_requests where account_id = @accountId);",
                ("accountId", cancelledEmailAccountId))).ShouldBeFalse();

            (bool cancelledEmailComplete, string cancelledEmailCompleteCode) = await QueryBoolStatusAsync(
                connection,
                "select result, code from complete_account_email_change(@verifyKeyHash);",
                ("verifyKeyHash", "cancel-email-verify-hash"));
            cancelledEmailComplete.ShouldBeFalse();
            cancelledEmailCompleteCode.ShouldBe("ACCOUNT_ADJUST_TOKEN_MISMATCH");

            Guid staleEmailAccountId = Guid.NewGuid();
            await ExecuteAsync(
                connection,
                """
                insert into accounts(
                    account_id, email_address, username, hashed_password, web_key, salt_one, siv, nonce,
                    login_failures, verify_status, features, two_factor_auth_method)
                values (
                    @accountId, 'stale-email-change@example.com', 'stale-email-change-reader', @hashedPassword, 'stale-email-web-key', @saltOne, @siv, @nonce,
                    0, 1, 0, 0);
                """,
                ("accountId", staleEmailAccountId),
                ("hashedPassword", hashedPassword),
                ("saltOne", saltOne),
                ("siv", siv),
                ("nonce", nonce));

            Guid staleEmailAccountSecurityStamp = await QueryGuidAsync(connection, "select security_stamp from accounts where account_id = @accountId;", ("accountId", staleEmailAccountId));

            (bool staleEmailPending, string staleEmailPendingCode) = await QueryBoolStatusAsync(
                connection,
                "select result, code from cor17_fixture_request_email(@accountId, @accountSecurityStamp, @newEmailAddress, @verifyKeyHash, @expiration);",
                ("accountId", staleEmailAccountId),
                ("accountSecurityStamp", staleEmailAccountSecurityStamp),
                ("newEmailAddress", "claimed-later@example.com"),
                ("verifyKeyHash", "stale-email-verify-hash"),
                ("expiration", DateTimeOffset.UtcNow.AddHours(1)));
            staleEmailPending.ShouldBeTrue();
            staleEmailPendingCode.ShouldBe("ACCOUNT_ADJUST_EMAIL_VERIFICATION_PENDING");

            Guid claimingAccountId = Guid.NewGuid();
            await ExecuteAsync(
                connection,
                """
                insert into accounts(
                    account_id, email_address, username, hashed_password, web_key, salt_one, siv, nonce,
                    login_failures, verify_status, features, two_factor_auth_method)
                values (
                    @accountId, 'claimed-later@example.com', 'claimed-later-reader', @hashedPassword, 'claimed-later-web-key', @saltOne, @siv, @nonce,
                    0, 1, 0, 0);
                """,
                ("accountId", claimingAccountId),
                ("hashedPassword", hashedPassword),
                ("saltOne", saltOne),
                ("siv", siv),
                ("nonce", nonce));

            (bool staleEmailComplete, string staleEmailCompleteCode) = await QueryBoolStatusAsync(
                connection,
                "select result, code from complete_account_email_change(@verifyKeyHash);",
                ("verifyKeyHash", "stale-email-verify-hash"));
            staleEmailComplete.ShouldBeFalse();
            staleEmailCompleteCode.ShouldBe("ACCOUNT_ADJUST_DUPLICATE_EMAIL");

            (await QueryBoolAsync(
                connection,
                "select exists(select 1 from account_email_change_requests where account_id = @accountId);",
                ("accountId", staleEmailAccountId))).ShouldBeFalse();

            Guid purgeEmailAccountId = Guid.NewGuid();
            await ExecuteAsync(
                connection,
                """
                insert into accounts(
                    account_id, email_address, username, hashed_password, web_key, salt_one, siv, nonce,
                    login_failures, verify_status, features, two_factor_auth_method)
                values (
                    @accountId, 'purge-email-change@example.com', 'purge-email-change-reader', @hashedPassword, 'purge-email-web-key', @saltOne, @siv, @nonce,
                    0, 1, 0, 0);
                """,
                ("accountId", purgeEmailAccountId),
                ("hashedPassword", hashedPassword),
                ("saltOne", saltOne),
                ("siv", siv),
                ("nonce", nonce));

            Guid purgeEmailAccountSecurityStamp = await QueryGuidAsync(connection, "select security_stamp from accounts where account_id = @accountId;", ("accountId", purgeEmailAccountId));

            await ExecuteAsync(
                connection,
                """
                insert into account_email_change_requests(
                    account_id, new_email_address, verify_key_hash, requested_at, expiration, account_security_stamp)
                values (
                    @accountId, 'expired-email-change@example.com', 'expired-email-change-verify-hash', now() - interval '2 hours', now() - interval '1 hour', @accountSecurityStamp);
                """,
                ("accountId", purgeEmailAccountId),
                ("accountSecurityStamp", purgeEmailAccountSecurityStamp));

            (bool purgeEmailResult, string purgeEmailCode, int purgedEmailCount) = await QueryBoolStatusCountAsync(
                connection,
                "select result, code, deleted_count from purge_expired_account_email_change_requests(now());");
            purgeEmailResult.ShouldBeTrue();
            purgeEmailCode.ShouldBe("ACCOUNT_ADJUST_PURGE_SUCCEEDED");
            purgedEmailCount.ShouldBeGreaterThanOrEqualTo(1);

            (await QueryBoolAsync(
                connection,
                "select exists(select 1 from account_email_change_requests where account_id = @accountId);",
                ("accountId", purgeEmailAccountId))).ShouldBeFalse();

            (bool emailChanged, string emailChangedCode) = await QueryBoolStatusAsync(
                connection,
                "select result, code from complete_account_email_change(@verifyKeyHash);",
                ("verifyKeyHash", "verify-hash"));
            emailChanged.ShouldBeTrue();
            emailChangedCode.ShouldBe("ACCOUNT_ADJUST_SUCCEEDED");

            (await QueryStringAsync(
                connection,
                "select email_address from accounts where account_id = @accountId;",
                ("accountId", accountId))).ShouldBe("new-reader@example.com");

            (short postEmailTrustStatus, string postEmailTrustCode) = await QueryShortStatusAsync(
                connection,
                "select status, code from validate_cached_session_trust(@accessTokenHash, @accountId, @securityStamp, @accountSecurityStamp);",
                ("accessTokenHash", "refreshed-active-hash"),
                ("accountId", accountId),
                ("securityStamp", refreshedActiveSecurityStamp),
                ("accountSecurityStamp", accountSecurityStamp));
            postEmailTrustStatus.ShouldBe((short)6);
            postEmailTrustCode.ShouldBe("ACCOUNT_SECURITY_STAMP_MISMATCH");

            accountSecurityStamp = await QueryGuidAsync(connection, "select security_stamp from accounts where account_id = @accountId;", ("accountId", accountId));

            // Current destructive authority: explicit completed-attestation/publication fixture.
            string deleteHash="combined-delete-proof";
            (await QueryBoolStatusAsync(connection,
                "select result,code from cor18_fixture_request_delete(@accountId,@stamp,'fixture-passphrase',@hash,clock_timestamp()+interval '1 hour',interval '15 minutes',interval '1 day',8::smallint)",
                ("accountId",accountId),("stamp",accountSecurityStamp),("hash",deleteHash))).Item1.ShouldBeTrue();
            (await QueryBoolStatusAsync(connection,
                "select result,code from cor18_fixture_request_delete(@accountId,@stamp,null,'replacement',clock_timestamp()+interval '1 hour',interval '15 minutes',interval '1 day',8::smallint)",
                ("accountId",accountId),("stamp",accountSecurityStamp))).Item2.ShouldBe("ACCOUNT_DELETE_RATE_LIMITED");
            (await QueryBoolStatusAsync(connection,"select result,code from verify_account_delete_token(@hash)",("hash",deleteHash))).Item1.ShouldBeTrue();
            (await QueryBoolStatusAsync(connection,"select result,code from verify_account_delete_token(@hash)",("hash",deleteHash))).Item1.ShouldBeTrue();
            (await QueryInt32Async(connection,"select count(*)::integer from account_delete_events where account_id=@account and event_type='VERIFIED'",("account",accountId))).ShouldBe(1);
            (await QueryBoolStatusAsync(connection,Cor18DeleteSql.Commit("'"+accountId+"'::uuid","'"+accountSecurityStamp+"'::uuid",deleteHash,false))).Item2.ShouldBe("ACCOUNT_DELETE_TOKEN_MISMATCH");
            (await QueryInt32Async(connection,"select failed_finalize_attempts from account_delete_budgets where account_id=@account",("account",accountId))).ShouldBe(1);
            (await QueryBoolStatusAsync(connection,Cor18DeleteSql.Commit("'"+accountId+"'::uuid","'"+accountSecurityStamp+"'::uuid",deleteHash))).Item1.ShouldBeTrue();
            (await QueryBoolAsync(connection,"select exists(select 1 from accounts where account_id=@account)",("account",accountId))).ShouldBeFalse();
            (await QueryInt32Async(connection,"select count(*)::integer from account_delete_events where account_id=@account and event_type='COMPLETED'",("account",accountId))).ShouldBe(1);

        }
        finally
        {
            await ExecuteAsync(connection, $"drop schema if exists {schema} cascade;");
        }
    }

    [Fact]
    public async Task Effective_cutoff_is_preserved_and_enforced_by_credential_lookup_set_session_and_rotation()
    {
        await using NpgsqlConnection connection = await OpenDeferredSqlContractConnectionAsync();

        string schema = "contract_cutoff_" + Guid.NewGuid().ToString("N");

        try
        {
            await ExecuteAsync(connection, $"create schema {schema};");
            await ExecuteAsync(connection, $"set search_path to {schema};");
            await ExecuteAsync(connection, File.ReadAllText(BaselinePath()));
            await Cor17EmailSql.Install(connection);
            await Cor18DeleteSql.Install(connection);

            byte[] hashedPassword = Enumerable.Repeat((byte)21, 128).ToArray();
            byte[] saltOne = Enumerable.Repeat((byte)22, 64).ToArray();
            byte[] siv = Enumerable.Repeat((byte)23, 32).ToArray();
            byte[] nonce = Enumerable.Repeat((byte)24, 16).ToArray();
            byte[] oldRefreshToken = Enumerable.Repeat((byte)25, 64).ToArray();
            byte[] newRefreshToken = Enumerable.Repeat((byte)26, 64).ToArray();

            Guid preserveAccountId = Guid.NewGuid();
            DateTimeOffset preserveAccountCutOff = DateTimeOffset.UtcNow.AddMinutes(20);
            DateTimeOffset preserveSessionCutOff = DateTimeOffset.UtcNow.AddMinutes(5);

            await ExecuteAsync(
                connection,
                """
                insert into accounts(
                    account_id, email_address, username, hashed_password, web_key, salt_one, siv, nonce,
                    login_failures, verify_status, features, two_factor_auth_method, cut_off)
                values (
                    @accountId, 'cutoff-preserve@example.com', 'cutoff-preserve', @hashedPassword, 'web-key-' || gen_random_uuid()::text, @saltOne, @siv, @nonce,
                    0, 1, 0, 0, @accountCutOff);
                """,
                ("accountId", preserveAccountId),
                ("hashedPassword", hashedPassword),
                ("saltOne", saltOne),
                ("siv", siv),
                ("nonce", nonce),
                ("accountCutOff", preserveAccountCutOff));

            Guid preserveAccountSecurityStamp = await QueryGuidAsync(connection, "select security_stamp from accounts where account_id = @accountId;", ("accountId", preserveAccountId));

            await ExecuteAsync(
                connection,
                """
                insert into sessions(
                    access_token_hash, account_id, refresh_token, refreshes, refresh_limit, created_on, session_lifespan,
                    access_expiration, session_expiration, cut_off, features, account_security_stamp)
                values (
                    'cutoff-preserve-old', @accountId, @oldRefreshToken, 0, 5, now() - interval '5 minutes', interval '7 days',
                    now() + interval '10 minutes', now() + interval '1 hour', @sessionCutOff, 0, @accountSecurityStamp);
                """,
                ("accountId", preserveAccountId),
                ("oldRefreshToken", oldRefreshToken),
                ("sessionCutOff", preserveSessionCutOff),
                ("accountSecurityStamp", preserveAccountSecurityStamp));

            DateTimeOffset credentialCutOff = await QueryDateTimeOffsetAsync(
                connection,
                "select cut_off from check_account_emailaddress_creds(@emailAddress);",
                ("emailAddress", "cutoff-preserve@example.com"));
            Math.Abs((credentialCutOff - preserveSessionCutOff).TotalSeconds).ShouldBeLessThan(1);

            (short preserveRotateStatus, string preserveRotateCode) = await QueryShortStatusAsync(
                connection,
                """
                select status, code from rotate_active_session(
                    @accountId, @expectedOldAccessTokenHash, @newAccessTokenHash, @refreshToken, @refreshes, @limit,
                    @createdOn, @sessionLifespan, @accessExpiration, @sessionExpiration, @cutOff, @features, @securityStamp, @accountSecurityStamp);
                """,
                ("accountId", preserveAccountId),
                ("expectedOldAccessTokenHash", "cutoff-preserve-old"),
                ("newAccessTokenHash", "cutoff-preserve-new"),
                ("refreshToken", newRefreshToken),
                ("refreshes", (short)1),
                ("limit", (short)5),
                ("createdOn", DateTimeOffset.UtcNow),
                ("sessionLifespan", TimeSpan.FromDays(7)),
                ("accessExpiration", DateTimeOffset.UtcNow.AddMinutes(10)),
                ("sessionExpiration", DateTimeOffset.UtcNow.AddDays(7)),
                ("cutOff", credentialCutOff),
                ("features", (short)0),
                ("securityStamp", Guid.Parse("dddddddd-dddd-dddd-dddd-dddddddddddd")),
                ("accountSecurityStamp", preserveAccountSecurityStamp));

            preserveRotateStatus.ShouldBe((short)1);
            preserveRotateCode.ShouldBe("SUCCEEDED");

            DateTimeOffset preservedRotatedCutOff = await QueryDateTimeOffsetAsync(
                connection,
                "select cut_off from get_session(@accessTokenHash);",
                ("accessTokenHash", "cutoff-preserve-new"));
            Math.Abs((preservedRotatedCutOff - preserveSessionCutOff).TotalSeconds).ShouldBeLessThan(1);

            Guid expiredAccountId = Guid.NewGuid();
            await ExecuteAsync(
                connection,
                """
                insert into accounts(
                    account_id, email_address, username, hashed_password, web_key, salt_one, siv, nonce,
                    login_failures, verify_status, features, two_factor_auth_method, cut_off)
                values (
                    @accountId, 'cutoff-expired@example.com', 'cutoff-expired', @hashedPassword, 'web-key-' || gen_random_uuid()::text, @saltOne, @siv, @nonce,
                    0, 1, 0, 0, now() - interval '1 minute');
                """,
                ("accountId", expiredAccountId),
                ("hashedPassword", hashedPassword),
                ("saltOne", saltOne),
                ("siv", siv),
                ("nonce", nonce));

            Guid expiredAccountSecurityStamp = await QueryGuidAsync(connection, "select security_stamp from accounts where account_id = @accountId;", ("accountId", expiredAccountId));
            (short expiredSetStatus, string expiredSetCode) = await QueryShortStatusAsync(
                connection,
                """
                select result, code from set_session(
                    @accessTokenHash, @accountId, @refreshToken, @refreshes, @limit, @createdOn, @sessionLifespan,
                    @accessExpiration, @sessionExpiration, @cutOff, @features, @securityStamp, @accountSecurityStamp);
                """,
                ("accessTokenHash", "cutoff-expired-new"),
                ("accountId", expiredAccountId),
                ("refreshToken", newRefreshToken),
                ("refreshes", (short)0),
                ("limit", (short)5),
                ("createdOn", DateTimeOffset.UtcNow),
                ("sessionLifespan", TimeSpan.FromDays(7)),
                ("accessExpiration", DateTimeOffset.UtcNow.AddMinutes(10)),
                ("sessionExpiration", DateTimeOffset.UtcNow.AddDays(7)),
                ("cutOff", DateTimeOffset.UtcNow.AddHours(1)),
                ("features", (short)0),
                ("securityStamp", Guid.Parse("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee")),
                ("accountSecurityStamp", expiredAccountSecurityStamp));

            expiredSetStatus.ShouldBe((short)5000);
            expiredSetCode.ShouldBe("ACCOUNT_CUT_OFF_EXPIRED");
            (await QueryStringAsync(connection, "select access_token_hash from sessions where access_token_hash = 'cutoff-expired-new';")).ShouldBeNull();

            Guid setCapAccountId = Guid.NewGuid();
            DateTimeOffset setCapAccountCutOff = DateTimeOffset.UtcNow.AddMinutes(7);
            await ExecuteAsync(
                connection,
                """
                insert into accounts(
                    account_id, email_address, username, hashed_password, web_key, salt_one, siv, nonce,
                    login_failures, verify_status, features, two_factor_auth_method, cut_off)
                values (
                    @accountId, 'cutoff-set-cap@example.com', 'cutoff-set-cap', @hashedPassword, 'web-key-' || gen_random_uuid()::text, @saltOne, @siv, @nonce,
                    0, 1, 0, 0, @accountCutOff);
                """,
                ("accountId", setCapAccountId),
                ("hashedPassword", hashedPassword),
                ("saltOne", saltOne),
                ("siv", siv),
                ("nonce", nonce),
                ("accountCutOff", setCapAccountCutOff));

            Guid setCapAccountSecurityStamp = await QueryGuidAsync(connection, "select security_stamp from accounts where account_id = @accountId;", ("accountId", setCapAccountId));
            (short setCapStatus, string setCapCode) = await QueryShortStatusAsync(
                connection,
                """
                select result, code from set_session(
                    @accessTokenHash, @accountId, @refreshToken, @refreshes, @limit, @createdOn, @sessionLifespan,
                    @accessExpiration, @sessionExpiration, @cutOff, @features, @securityStamp, @accountSecurityStamp);
                """,
                ("accessTokenHash", "cutoff-set-cap-new"),
                ("accountId", setCapAccountId),
                ("refreshToken", newRefreshToken),
                ("refreshes", (short)0),
                ("limit", (short)5),
                ("createdOn", DateTimeOffset.UtcNow),
                ("sessionLifespan", TimeSpan.FromDays(7)),
                ("accessExpiration", DateTimeOffset.UtcNow.AddMinutes(10)),
                ("sessionExpiration", DateTimeOffset.UtcNow.AddDays(7)),
                ("cutOff", DateTimeOffset.UtcNow.AddHours(1)),
                ("features", (short)0),
                ("securityStamp", Guid.Parse("ffffffff-ffff-ffff-ffff-ffffffffffff")),
                ("accountSecurityStamp", setCapAccountSecurityStamp));

            setCapStatus.ShouldBe((short)1);
            setCapCode.ShouldBe("SUCCESSFUL");
            DateTimeOffset setCappedCutOff = await QueryDateTimeOffsetAsync(connection, "select cut_off from get_session(@accessTokenHash);", ("accessTokenHash", "cutoff-set-cap-new"));
            Math.Abs((setCappedCutOff - setCapAccountCutOff).TotalSeconds).ShouldBeLessThan(1);

            Guid rotateCapAccountId = Guid.NewGuid();
            DateTimeOffset rotateCapAccountCutOff = DateTimeOffset.UtcNow.AddMinutes(12);
            await ExecuteAsync(
                connection,
                """
                insert into accounts(
                    account_id, email_address, username, hashed_password, web_key, salt_one, siv, nonce,
                    login_failures, verify_status, features, two_factor_auth_method, cut_off)
                values (
                    @accountId, 'cutoff-rotate-cap@example.com', 'cutoff-rotate-cap', @hashedPassword, 'web-key-' || gen_random_uuid()::text, @saltOne, @siv, @nonce,
                    0, 1, 0, 0, @accountCutOff);
                """,
                ("accountId", rotateCapAccountId),
                ("hashedPassword", hashedPassword),
                ("saltOne", saltOne),
                ("siv", siv),
                ("nonce", nonce),
                ("accountCutOff", rotateCapAccountCutOff));

            Guid rotateCapAccountSecurityStamp = await QueryGuidAsync(connection, "select security_stamp from accounts where account_id = @accountId;", ("accountId", rotateCapAccountId));
            await ExecuteAsync(
                connection,
                """
                insert into sessions(
                    access_token_hash, account_id, refresh_token, refreshes, refresh_limit, created_on, session_lifespan,
                    access_expiration, session_expiration, features, account_security_stamp)
                values (
                    'cutoff-rotate-cap-old', @accountId, @oldRefreshToken, 0, 5, now() - interval '5 minutes', interval '7 days',
                    now() + interval '10 minutes', now() + interval '1 hour', 0, @accountSecurityStamp);
                """,
                ("accountId", rotateCapAccountId),
                ("oldRefreshToken", oldRefreshToken),
                ("accountSecurityStamp", rotateCapAccountSecurityStamp));

            (short rotateCapStatus, string rotateCapCode) = await QueryShortStatusAsync(
                connection,
                """
                select status, code from rotate_active_session(
                    @accountId, @expectedOldAccessTokenHash, @newAccessTokenHash, @refreshToken, @refreshes, @limit,
                    @createdOn, @sessionLifespan, @accessExpiration, @sessionExpiration, @cutOff, @features, @securityStamp, @accountSecurityStamp);
                """,
                ("accountId", rotateCapAccountId),
                ("expectedOldAccessTokenHash", "cutoff-rotate-cap-old"),
                ("newAccessTokenHash", "cutoff-rotate-cap-new"),
                ("refreshToken", newRefreshToken),
                ("refreshes", (short)1),
                ("limit", (short)5),
                ("createdOn", DateTimeOffset.UtcNow),
                ("sessionLifespan", TimeSpan.FromDays(7)),
                ("accessExpiration", DateTimeOffset.UtcNow.AddMinutes(10)),
                ("sessionExpiration", DateTimeOffset.UtcNow.AddDays(7)),
                ("cutOff", DateTimeOffset.UtcNow.AddHours(1)),
                ("features", (short)0),
                ("securityStamp", Guid.Parse("aaaaaaaa-1111-2222-3333-444444444444")),
                ("accountSecurityStamp", rotateCapAccountSecurityStamp));

            rotateCapStatus.ShouldBe((short)1);
            rotateCapCode.ShouldBe("SUCCEEDED");
            DateTimeOffset rotateCappedCutOff = await QueryDateTimeOffsetAsync(connection, "select cut_off from get_session(@accessTokenHash);", ("accessTokenHash", "cutoff-rotate-cap-new"));
            Math.Abs((rotateCappedCutOff - rotateCapAccountCutOff).TotalSeconds).ShouldBeLessThan(1);
        }
        finally
        {
            await ExecuteAsync(connection, $"drop schema if exists {schema} cascade;");
        }
    }

    [Fact]
    public async Task Canonical_sql_baseline_creates_registration_verification_contracts()
    {
        await using NpgsqlConnection connection = await OpenDeferredSqlContractConnectionAsync();

        string schema = "contract_registration_" + Guid.NewGuid().ToString("N");

        try
        {
            await ExecuteAsync(connection, $"create schema {schema};");
            await ExecuteAsync(connection, $"set search_path to {schema};");
            await ExecuteAsync(connection, File.ReadAllText(BaselinePath()));
            await Cor17EmailSql.Install(connection);
            await Cor18DeleteSql.Install(connection);

            Guid accountId = Guid.NewGuid();
            byte[] hashedPassword = Enumerable.Repeat((byte)10, 128).ToArray();
            byte[] saltOne = Enumerable.Repeat((byte)11, 64).ToArray();
            byte[] siv = Enumerable.Repeat((byte)12, 32).ToArray();
            byte[] nonce = Enumerable.Repeat((byte)13, 16).ToArray();

            await using (var setupCommand = new NpgsqlCommand("select verification_index, outcome from setup_account_both(@accountId, @username, @emailAddress, @webKey, @hashedPassword, @saltOne, @siv, @nonce, @country, @verifyKeyHash, now(), interval '2 days');", connection))
            {
                AddParameters(
                    setupCommand,
                    ("accountId", accountId),
                    ("username", "registration-reader"),
                    ("emailAddress", "registration@example.com"),
                    ("webKey", "registration-web-key"),
                    ("hashedPassword", hashedPassword),
                    ("saltOne", saltOne),
                    ("siv", siv),
                    ("nonce", nonce),
                    ("country", (short)1),
                    ("verifyKeyHash", "verify-key-hash"));

                await using NpgsqlDataReader reader = await setupCommand.ExecuteReaderAsync();
                (await reader.ReadAsync()).ShouldBeTrue();
                reader.IsDBNull(0).ShouldBeFalse();
                reader.GetInt16(1).ShouldBe((short)8000);
            }

            long verificationIndex = await QueryInt64Async(
                connection,
                "select verification_index from account_verifications where account_id = @accountId;",
                ("accountId", accountId));

            (await QueryInt32Async(
                connection,
                "select verify_status from accounts where account_id = @accountId;",
                ("accountId", accountId))).ShouldBe(0);

            (await QueryBoolAsync(
                connection,
                "select result from start_verify_account(@accountId, @verificationIndex);",
                ("accountId", accountId),
                ("verificationIndex", verificationIndex))).ShouldBeTrue();

            (await QueryInt32Async(
                connection,
                "select verify_status from accounts where account_id = @accountId;",
                ("accountId", accountId))).ShouldBe(2);

            (await QueryScalarAsync(
                connection,
                "select unlock_when from accounts where account_id = @accountId;",
                ("accountId", accountId))).ShouldBeNull();

            await using (var resendCommand = new NpgsqlCommand("select result, code, email_address from resend_verify_account(@emailAddress, @verifyKeyHash, interval '3 days');", connection))
            {
                AddParameters(
                    resendCommand,
                    ("emailAddress", "registration@example.com"),
                    ("verifyKeyHash", "verify-key-hash-resend"));

                await using NpgsqlDataReader resendReader = await resendCommand.ExecuteReaderAsync();
                (await resendReader.ReadAsync()).ShouldBeTrue();
                resendReader.GetBoolean(0).ShouldBeTrue();
                resendReader.GetString(1).ShouldBe("VERIFICATION_RESEND_STARTED");
                resendReader.GetString(2).ShouldBe("registration@example.com");
            }

            (await QueryStringAsync(
                connection,
                "select verify_key_hash from verify_account_for_use(@verifyKeyHash);",
                ("verifyKeyHash", "verify-key-hash-resend"))).ShouldBe("verify-key-hash-resend");

            (await QueryStringAsync(
                connection,
                "select verify_key_hash from verify_account_for_use(@verifyKeyHash);",
                ("verifyKeyHash", "verify-key-hash"))).ShouldBe("verify-key-hash");

            (await QueryBoolAsync(
                connection,
                "select result from complete_verify_account(@accountId, @verifyKeyHash, (select proof_version from account_verifications where verify_key_hash=@verifyKeyHash), (select security_stamp from accounts where account_id=@accountId));",
                ("accountId", accountId),
                ("verifyKeyHash", "verify-key-hash-resend"))).ShouldBeTrue();

            (await QueryInt32Async(
                connection,
                "select verify_status from accounts where account_id = @accountId;",
                ("accountId", accountId))).ShouldBe(1);

            await using var duplicateEmailCommand = new NpgsqlCommand("select outcome from setup_account_email(@accountId, @emailAddress, @webKey, @hashedPassword, @saltOne, @siv, @nonce, @country, @verifyKeyHash, now(), interval '2 days');", connection);
            AddParameters(
                duplicateEmailCommand,
                ("accountId", Guid.NewGuid()),
                ("emailAddress", "registration@example.com"),
                ("webKey", "registration-web-key-2"),
                ("hashedPassword", hashedPassword),
                ("saltOne", saltOne),
                ("siv", siv),
                ("nonce", nonce),
                ("country", (short)1),
                ("verifyKeyHash", "another-verify-key-hash"));
            object? duplicateOutcome = await duplicateEmailCommand.ExecuteScalarAsync();
            Convert.ToInt16(duplicateOutcome).ShouldBe((short)8040);
        }
        finally
        {
            await ExecuteAsync(connection, $"drop schema if exists {schema} cascade;");
        }
    }


    [Fact]
    public async Task Validate_cached_session_trust_returns_expected_contract_statuses()
    {
        await using NpgsqlConnection connection = await OpenDeferredSqlContractConnectionAsync();

        string schema = "contract_trust_" + Guid.NewGuid().ToString("N");

        try
        {
            await ExecuteAsync(connection, $"create schema {schema};");
            await ExecuteAsync(connection, $"set search_path to {schema};");
            await ExecuteAsync(connection, File.ReadAllText(BaselinePath()));
            await Cor17EmailSql.Install(connection);
            await Cor18DeleteSql.Install(connection);

            Guid accountId = Guid.NewGuid();
            await ExecuteAsync(
                connection,
                """
                insert into accounts(account_id, email_address, username, two_factor_auth_method)
                values (@accountId, 'trust@example.com', 'trust-reader', 0);
                """,
                ("accountId", accountId));

            Guid accountSecurityStamp = await QueryGuidAsync(
                connection,
                "select security_stamp from accounts where account_id = @accountId;",
                ("accountId", accountId));

            await ExecuteAsync(
                connection,
                """
                insert into sessions(access_token_hash, account_id, access_expiration, session_expiration, cut_off, account_security_stamp)
                values ('trust-valid-hash', @accountId, now() + interval '10 minutes', now() + interval '1 hour', now() + interval '30 minutes', @accountSecurityStamp);
                """,
                ("accountId", accountId),
                ("accountSecurityStamp", accountSecurityStamp));

            Guid sessionSecurityStamp = await QueryGuidAsync(
                connection,
                "select security_stamp from sessions where access_token_hash = 'trust-valid-hash';");

            (short validStatus, string validCode) = await QueryShortStatusAsync(
                connection,
                "select status, code from validate_cached_session_trust(@accessTokenHash, @accountId, @securityStamp, @accountSecurityStamp);",
                ("accessTokenHash", "trust-valid-hash"),
                ("accountId", accountId),
                ("securityStamp", sessionSecurityStamp),
                ("accountSecurityStamp", accountSecurityStamp));
            validStatus.ShouldBe((short)1);
            validCode.ShouldBe("VALID");

            (short missingSessionStatus, string missingSessionCode) = await QueryShortStatusAsync(
                connection,
                "select status, code from validate_cached_session_trust(@accessTokenHash, @accountId, @securityStamp, @accountSecurityStamp);",
                ("accessTokenHash", "trust-missing-hash"),
                ("accountId", accountId),
                ("securityStamp", sessionSecurityStamp),
                ("accountSecurityStamp", accountSecurityStamp));
            missingSessionStatus.ShouldBe((short)2);
            missingSessionCode.ShouldBe("SESSION_NOT_FOUND");

            (short missingAccountStatus, string missingAccountCode) = await QueryShortStatusAsync(
                connection,
                "select status, code from validate_cached_session_trust(@accessTokenHash, @accountId, @securityStamp, @accountSecurityStamp);",
                ("accessTokenHash", "trust-valid-hash"),
                ("accountId", Guid.NewGuid()),
                ("securityStamp", sessionSecurityStamp),
                ("accountSecurityStamp", accountSecurityStamp));
            missingAccountStatus.ShouldBe((short)3);
            missingAccountCode.ShouldBe("ACCOUNT_NOT_FOUND");

            (short sessionStampMismatchStatus, string sessionStampMismatchCode) = await QueryShortStatusAsync(
                connection,
                "select status, code from validate_cached_session_trust(@accessTokenHash, @accountId, @securityStamp, @accountSecurityStamp);",
                ("accessTokenHash", "trust-valid-hash"),
                ("accountId", accountId),
                ("securityStamp", Guid.NewGuid()),
                ("accountSecurityStamp", accountSecurityStamp));
            sessionStampMismatchStatus.ShouldBe((short)4);
            sessionStampMismatchCode.ShouldBe("SECURITY_STAMP_MISMATCH");

            (short accountStampMismatchStatus, string accountStampMismatchCode) = await QueryShortStatusAsync(
                connection,
                "select status, code from validate_cached_session_trust(@accessTokenHash, @accountId, @securityStamp, @accountSecurityStamp);",
                ("accessTokenHash", "trust-valid-hash"),
                ("accountId", accountId),
                ("securityStamp", sessionSecurityStamp),
                ("accountSecurityStamp", Guid.NewGuid()));
            accountStampMismatchStatus.ShouldBe((short)6);
            accountStampMismatchCode.ShouldBe("ACCOUNT_SECURITY_STAMP_MISMATCH");

            Guid accountCutoffId = Guid.NewGuid();
            await ExecuteAsync(
                connection,
                """
                insert into accounts(account_id, email_address, username, cut_off, two_factor_auth_method)
                values (@accountId, 'account-cutoff-trust@example.com', 'account-cutoff-trust', now() - interval '1 minute', 0);
                """,
                ("accountId", accountCutoffId));
            Guid accountCutoffStamp = await QueryGuidAsync(connection, "select security_stamp from accounts where account_id = @accountId;", ("accountId", accountCutoffId));
            await ExecuteAsync(
                connection,
                """
                insert into sessions(access_token_hash, account_id, access_expiration, session_expiration, account_security_stamp)
                values ('trust-account-cutoff-hash', @accountId, now() + interval '10 minutes', now() + interval '1 hour', @accountSecurityStamp);
                """,
                ("accountId", accountCutoffId),
                ("accountSecurityStamp", accountCutoffStamp));
            Guid accountCutoffSessionStamp = await QueryGuidAsync(connection, "select security_stamp from sessions where access_token_hash = 'trust-account-cutoff-hash';");
            var accountCutoffTrust = await QueryTrustStateAsync(
                connection,
                "select status, code, access_expiration, session_expiration, cut_off, security_stamp, account_security_stamp from validate_cached_session_trust(@accessTokenHash, @accountId, @securityStamp, @accountSecurityStamp);",
                ("accessTokenHash", "trust-account-cutoff-hash"),
                ("accountId", accountCutoffId),
                ("securityStamp", accountCutoffSessionStamp),
                ("accountSecurityStamp", accountCutoffStamp));
            accountCutoffTrust.Status.ShouldBe((short)5);
            accountCutoffTrust.Code.ShouldBe("SESSION_EXPIRED");
            accountCutoffTrust.CutOff.ShouldNotBeNull();
            accountCutoffTrust.CutOff.Value.ShouldBeLessThan(DateTimeOffset.UtcNow.AddSeconds(5));

            DateTimeOffset hydratedAccountCutoff = await QueryDateTimeOffsetAsync(
                connection,
                "select cut_off from get_session(@accessTokenHash);",
                ("accessTokenHash", "trust-account-cutoff-hash"));
            hydratedAccountCutoff.ShouldBeLessThan(DateTimeOffset.UtcNow.AddSeconds(5));

            Guid sessionCutoffId = Guid.NewGuid();
            await ExecuteAsync(
                connection,
                """
                insert into accounts(account_id, email_address, username, two_factor_auth_method)
                values (@accountId, 'session-cutoff-trust@example.com', 'session-cutoff-trust', 0);
                """,
                ("accountId", sessionCutoffId));
            Guid sessionCutoffAccountStamp = await QueryGuidAsync(connection, "select security_stamp from accounts where account_id = @accountId;", ("accountId", sessionCutoffId));
            await ExecuteAsync(
                connection,
                """
                insert into sessions(access_token_hash, account_id, access_expiration, session_expiration, cut_off, account_security_stamp)
                values ('trust-session-cutoff-hash', @accountId, now() + interval '10 minutes', now() + interval '1 hour', now() - interval '1 minute', @accountSecurityStamp);
                """,
                ("accountId", sessionCutoffId),
                ("accountSecurityStamp", sessionCutoffAccountStamp));
            Guid sessionCutoffSecurityStamp = await QueryGuidAsync(connection, "select security_stamp from sessions where access_token_hash = 'trust-session-cutoff-hash';");
            (short sessionCutoffStatus, string sessionCutoffCode) = await QueryShortStatusAsync(
                connection,
                "select status, code from validate_cached_session_trust(@accessTokenHash, @accountId, @securityStamp, @accountSecurityStamp);",
                ("accessTokenHash", "trust-session-cutoff-hash"),
                ("accountId", sessionCutoffId),
                ("securityStamp", sessionCutoffSecurityStamp),
                ("accountSecurityStamp", sessionCutoffAccountStamp));
            sessionCutoffStatus.ShouldBe((short)5);
            sessionCutoffCode.ShouldBe("SESSION_EXPIRED");
        }
        finally
        {
            await ExecuteAsync(connection, $"drop schema if exists {schema} cascade;");
        }
    }

    [Fact]
    public Task Unversioned_pending_login_entrypoints_are_absent_from_current_setup()
        => SqlContractFixture.RunAsync(async (fixture, cancellation) =>
        {
            var connection = await fixture.OpenConnectionAsync();
            await using var command = new NpgsqlCommand("select count(*) from pg_proc p join pg_namespace n on p.pronamespace=n.oid where n.nspname=current_schema() and p.proname in ('begin_twofactor_auth_detail','set_twofactor_auth_detail','successful_twofactor_auth','record_twofactor_challenge_issued','record_twofactor_challenge_failure','cancel_twofactor_challenge_issued','is_pending_twofactor_session_current')", connection);
            ((long)(await command.ExecuteScalarAsync(cancellation))!).ShouldBe(0);
        }, TestContext.Current.CancellationToken);


    [Fact]
    public async Task Logout_contracts_expire_current_session_rotate_account_stamp_and_clear_pending_state()
    {
        await using NpgsqlConnection connection = await OpenDeferredSqlContractConnectionAsync();

        string schema = "contract_logout_" + Guid.NewGuid().ToString("N");

        try
        {
            await ExecuteAsync(connection, $"create schema {schema};");
            await ExecuteAsync(connection, $"set search_path to {schema};");
            await ExecuteAsync(connection, File.ReadAllText(BaselinePath()));
            await Cor17EmailSql.Install(connection);
            await Cor18DeleteSql.Install(connection);

            Guid accountId = Guid.NewGuid();

            await ExecuteAsync(
                connection,
                """
                insert into accounts(account_id, email_address, username, two_factor_access_token, two_auth_usage)
                values (@accountId, 'logout-contract@example.com', 'logout-contract', 'pending-token-hash', 1);
                """,
                ("accountId", accountId));

            Guid originalStamp = await QueryGuidAsync(
                connection,
                "select security_stamp from accounts where account_id = @accountId;",
                ("accountId", accountId));

            await ExecuteAsync(
                connection,
                """
                insert into sessions(access_token_hash, account_id, access_expiration, session_expiration, account_security_stamp)
                values
                    ('current-logout-hash', @accountId, now() + interval '10 minutes', now() + interval '2 hours', @accountSecurityStamp),
                    ('other-logout-hash', @accountId, now() + interval '10 minutes', now() + interval '2 hours', @accountSecurityStamp),
                    ('managed-revoke-hash', @accountId, now() + interval '10 minutes', now() + interval '2 hours', @accountSecurityStamp);
                """,
                ("accountId", accountId),
                ("accountSecurityStamp", originalStamp));

            Guid currentSessionStamp = await QueryGuidAsync(
                connection,
                "select security_stamp from get_session(@accessTokenHash);",
                ("accessTokenHash", "current-logout-hash"));
            Guid otherSessionStamp = await QueryGuidAsync(
                connection,
                "select security_stamp from get_session(@accessTokenHash);",
                ("accessTokenHash", "other-logout-hash"));
            Guid managedSessionStamp = await QueryGuidAsync(
                connection,
                "select security_stamp from get_session(@accessTokenHash);",
                ("accessTokenHash", "managed-revoke-hash"));
            Guid managedSessionId = await QueryGuidAsync(
                connection,
                "select session_id from sessions where access_token_hash = @accessTokenHash;",
                ("accessTokenHash", "managed-revoke-hash"));

            (await QueryInt32Async(
                connection,
                "select count(*) from list_active_sessions(@accountId, @accountSecurityStamp, @currentAccessTokenHash);",
                ("accountId", accountId),
                ("accountSecurityStamp", originalStamp),
                ("currentAccessTokenHash", "current-logout-hash"))).ShouldBe(3);
            (await QueryBoolAsync(
                connection,
                "select is_current from list_active_sessions(@accountId, @accountSecurityStamp, @currentAccessTokenHash) where is_current = true;",
                ("accountId", accountId),
                ("accountSecurityStamp", originalStamp),
                ("currentAccessTokenHash", "current-logout-hash"))).ShouldBeTrue();

            (bool managedRevoked, string managedRevokedCode) = await QueryBoolStatusAsync(
                connection,
                "select result, code from revoke_session_for_account(@accountId, @targetSessionId, @accountSecurityStamp, @currentAccessTokenHash);",
                ("accountId", accountId),
                ("targetSessionId", managedSessionId),
                ("accountSecurityStamp", originalStamp),
                ("currentAccessTokenHash", "current-logout-hash"));
            managedRevoked.ShouldBeTrue();
            managedRevokedCode.ShouldBe("SESSION_REVOKED");

            (bool repeatedManagedRevoke, string repeatedManagedRevokeCode) = await QueryBoolStatusAsync(
                connection,
                "select result, code from revoke_session_for_account(@accountId, @targetSessionId, @accountSecurityStamp, @currentAccessTokenHash);",
                ("accountId", accountId),
                ("targetSessionId", managedSessionId),
                ("accountSecurityStamp", originalStamp),
                ("currentAccessTokenHash", "current-logout-hash"));
            repeatedManagedRevoke.ShouldBeTrue();
            repeatedManagedRevokeCode.ShouldBe("SESSION_ALREADY_MISSING_OR_STALE");

            (await QueryInt32Async(
                connection,
                "select count(*) from session_logout_events where account_id = @accountId and logout_scope = 'session' and code = 'SESSION_ALREADY_MISSING_OR_STALE';",
                ("accountId", accountId))).ShouldBe(1);

            (short managedTrustStatus, string managedTrustCode) = await QueryShortStatusAsync(
                connection,
                "select status, code from validate_cached_session_trust(@accessTokenHash, @accountId, @securityStamp, @accountSecurityStamp);",
                ("accessTokenHash", "managed-revoke-hash"),
                ("accountId", accountId),
                ("securityStamp", managedSessionStamp),
                ("accountSecurityStamp", originalStamp));
            managedTrustStatus.ShouldBe((short)5);
            managedTrustCode.ShouldBe("SESSION_EXPIRED");

            (bool currentLoggedOut, string currentLoggedOutCode) = await QueryBoolStatusAsync(
                connection,
                "select result, code from logout_current_session(@accountId, @accessTokenHash, @accountSecurityStamp);",
                ("accountId", accountId),
                ("accessTokenHash", "current-logout-hash"),
                ("accountSecurityStamp", originalStamp));
            currentLoggedOut.ShouldBeTrue();
            currentLoggedOutCode.ShouldBe("CURRENT_SESSION_LOGGED_OUT");

            (short currentTrustStatus, string currentTrustCode) = await QueryShortStatusAsync(
                connection,
                "select status, code from validate_cached_session_trust(@accessTokenHash, @accountId, @securityStamp, @accountSecurityStamp);",
                ("accessTokenHash", "current-logout-hash"),
                ("accountId", accountId),
                ("securityStamp", currentSessionStamp),
                ("accountSecurityStamp", originalStamp));
            currentTrustStatus.ShouldBe((short)5);
            currentTrustCode.ShouldBe("SESSION_EXPIRED");

            (short otherTrustStatusBeforeAll, string otherTrustCodeBeforeAll) = await QueryShortStatusAsync(
                connection,
                "select status, code from validate_cached_session_trust(@accessTokenHash, @accountId, @securityStamp, @accountSecurityStamp);",
                ("accessTokenHash", "other-logout-hash"),
                ("accountId", accountId),
                ("securityStamp", otherSessionStamp),
                ("accountSecurityStamp", originalStamp));
            otherTrustStatusBeforeAll.ShouldBe((short)1);
            otherTrustCodeBeforeAll.ShouldBe("VALID");

            (bool repeatedCurrentLogout, string repeatedCurrentLogoutCode) = await QueryBoolStatusAsync(
                connection,
                "select result, code from logout_current_session(@accountId, @accessTokenHash, @accountSecurityStamp);",
                ("accountId", accountId),
                ("accessTokenHash", "current-logout-hash"),
                ("accountSecurityStamp", originalStamp));
            repeatedCurrentLogout.ShouldBeTrue();
            repeatedCurrentLogoutCode.ShouldBe("SESSION_ALREADY_MISSING_OR_STALE");

            (bool logoutAllResult, string logoutAllCode, Guid? newAccountStamp) = await QueryLogoutAllStatusAsync(
                connection,
                "select result, code, account_security_stamp from logout_all_sessions(@accountId, @accountSecurityStamp);",
                ("accountId", accountId),
                ("accountSecurityStamp", originalStamp));
            logoutAllResult.ShouldBeTrue();
            logoutAllCode.ShouldBe("ALL_SESSIONS_LOGGED_OUT");
            newAccountStamp.ShouldNotBeNull();
            newAccountStamp!.Value.ShouldNotBe(originalStamp);

            (await QueryStringAsync(
                connection,
                "select two_factor_access_token from accounts where account_id = @accountId;",
                ("accountId", accountId))).ShouldBeNull();
            (await QueryStringAsync(
                connection,
                "select two_auth_usage::text from accounts where account_id = @accountId;",
                ("accountId", accountId))).ShouldBeNull();

            (await QueryBoolAsync(
                connection,
                "select session_expiration <= now() from sessions where access_token_hash = @accessTokenHash;",
                ("accessTokenHash", "other-logout-hash"))).ShouldBeTrue();

            (short otherTrustStatusAfterAll, string otherTrustCodeAfterAll) = await QueryShortStatusAsync(
                connection,
                "select status, code from validate_cached_session_trust(@accessTokenHash, @accountId, @securityStamp, @accountSecurityStamp);",
                ("accessTokenHash", "other-logout-hash"),
                ("accountId", accountId),
                ("securityStamp", otherSessionStamp),
                ("accountSecurityStamp", originalStamp));
            otherTrustStatusAfterAll.ShouldBe((short)6);
            otherTrustCodeAfterAll.ShouldBe("ACCOUNT_SECURITY_STAMP_MISMATCH");

            (bool staleLogoutAllResult, string staleLogoutAllCode, Guid? staleLogoutAllStamp) = await QueryLogoutAllStatusAsync(
                connection,
                "select result, code, account_security_stamp from logout_all_sessions(@accountId, @accountSecurityStamp);",
                ("accountId", accountId),
                ("accountSecurityStamp", originalStamp));
            staleLogoutAllResult.ShouldBeFalse();
            staleLogoutAllCode.ShouldBe("ACCOUNT_SECURITY_STAMP_MISMATCH");
            staleLogoutAllStamp.ShouldBeNull();

            (bool staleCurrentLogoutResult, string staleCurrentLogoutCode) = await QueryBoolStatusAsync(
                connection,
                "select result, code from logout_current_session(@accountId, @accessTokenHash, @accountSecurityStamp);",
                ("accountId", accountId),
                ("accessTokenHash", "other-logout-hash"),
                ("accountSecurityStamp", originalStamp));
            staleCurrentLogoutResult.ShouldBeFalse();
            staleCurrentLogoutCode.ShouldBe("ACCOUNT_SECURITY_STAMP_MISMATCH");

            (bool staleManagedRevokeResult, string staleManagedRevokeCode) = await QueryBoolStatusAsync(
                connection,
                "select result, code from revoke_session_for_account(@accountId, @targetSessionId, @accountSecurityStamp, @currentAccessTokenHash);",
                ("accountId", accountId),
                ("targetSessionId", managedSessionId),
                ("accountSecurityStamp", originalStamp),
                ("currentAccessTokenHash", "other-logout-hash"));
            staleManagedRevokeResult.ShouldBeFalse();
            staleManagedRevokeCode.ShouldBe("ACCOUNT_SECURITY_STAMP_MISMATCH");

            (await QueryInt32Async(
                connection,
                "select count(*) from session_logout_events where account_id = @accountId and completed = false and code = 'ACCOUNT_SECURITY_STAMP_MISMATCH';",
                ("accountId", accountId))).ShouldBe(3);
        }
        finally
        {
            await ExecuteAsync(connection, $"drop schema if exists {schema} cascade;");
        }
    }


    [Fact]
    public async Task Twofactor_setup_verification_keeps_one_pending_setup_per_account_and_blocks_replay()
    {
        await using var connection=await OpenDeferredSqlContractConnectionAsync();
        string schema="contract_2fa_setup_verify_"+Guid.NewGuid().ToString("N");
        try
        {
            await ExecuteAsync(connection,$"create schema {schema};set search_path to {schema};");
            await ExecuteAsync(connection,File.ReadAllText(BaselinePath()));
            Guid account=Guid.NewGuid();
            await ExecuteAsync(connection,"insert into accounts(account_id,email_address) values(@account,'setup@example.test')",("account",account));
            Guid stamp=await QueryGuidAsync(connection,"select security_stamp from accounts where account_id=@account",("account",account));
            var ct=TestContext.Current.CancellationToken;
            var first=Guid.NewGuid();var current=Guid.NewGuid();
            var grant=await Cor16EnrollmentSql.SeedGrant(connection,account,stamp,4,ct);
            (await QueryBoolStatusAsync(connection,Cor16EnrollmentSql.Begin(account,stamp,2,"first-proof",first,grant))).Item1.ShouldBeTrue();
            grant=await Cor16EnrollmentSql.SeedGrant(connection,account,stamp,4,ct);
            (await QueryBoolStatusAsync(connection,Cor16EnrollmentSql.Begin(account,stamp,2,"correct-proof",current,grant,first,1))).Item1.ShouldBeTrue();
            (await QueryInt32Async(connection,"select count(*)::int from two_factor_authentications where not verified")).ShouldBe(1);
            (await QueryStringAsync(connection,"select setup_version::text from two_factor_authentications")).ShouldBe("2");
            await Cor16EnrollmentSql.PublishFixture(connection,account,stamp,2,"correct-proof",current,ct);
            var wrong=await QueryBoolStatusAttemptsAsync(connection,Cor16EnrollmentSql.Verify(account,stamp,2,"wrong-proof",current,2,limit:3));
            wrong.Item1.ShouldBeFalse();wrong.Item2.ShouldBe("TWO_FACTOR_SETUP_INCORRECT");wrong.Item3.ShouldBe((short)1);
            var stale=await QueryBoolStatusAsync(connection,Cor16EnrollmentSql.Verify(account,stamp,1,"first-proof",first));
            stale.Item1.ShouldBeFalse();stale.Item2.ShouldBe("TWO_FACTOR_SETUP_CONFLICT");
            var verified=await QueryBoolStatusAsync(connection,Cor16EnrollmentSql.Verify(account,stamp,2,"correct-proof",current,2));
            verified.Item1.ShouldBeTrue();verified.Item2.ShouldBe("TWO_FACTOR_SETUP_VERIFIED");
            (await QueryBoolAsync(connection,"select verified and token is null and setup_request_id is null from two_factor_authentications")).ShouldBeTrue();
            (await QueryStringAsync(connection,"select two_factor_auth_method::text from accounts")).ShouldBe("2");
            (await QueryStringAsync(connection,"select two_auth_usage::text from accounts")).ShouldBe("1");
            var replay=await QueryBoolStatusAsync(connection,Cor16EnrollmentSql.Verify(account,stamp,2,"correct-proof",current,2));
            replay.Item1.ShouldBeFalse();replay.Item2.ShouldBe("TWO_FACTOR_SETUP_CONFLICT");
        }
        finally {await ExecuteAsync(connection,$"drop schema if exists {schema} cascade;");}
    }

    private static async Task ExecuteAsync(NpgsqlConnection connection, string sql, params (string Name, object? Value)[] parameters)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        AddParameters(command, parameters);
        await command.ExecuteNonQueryAsync();
    }

    private static async Task<bool> QueryBoolAsync(NpgsqlConnection connection, string sql, params (string Name, object? Value)[] parameters)
    {
        object? result = await QueryScalarAsync(connection, sql, parameters);
        result.ShouldNotBeNull();
        return (bool)result;
    }

    private static async Task<Guid> QueryGuidAsync(NpgsqlConnection connection, string sql, params (string Name, object? Value)[] parameters)
    {
        object? result = await QueryScalarAsync(connection, sql, parameters);
        result.ShouldNotBeNull();
        return (Guid)result;
    }

    private static async Task<int> QueryInt32Async(NpgsqlConnection connection, string sql, params (string Name, object? Value)[] parameters)
    {
        object? result = await QueryScalarAsync(connection, sql, parameters);
        result.ShouldNotBeNull();
        return Convert.ToInt32(result);
    }

    private static async Task<long> QueryInt64Async(NpgsqlConnection connection, string sql, params (string Name, object? Value)[] parameters)
    {
        object? result = await QueryScalarAsync(connection, sql, parameters);
        result.ShouldNotBeNull();
        return Convert.ToInt64(result);
    }

    private static async Task<byte[]> QueryBytesAsync(NpgsqlConnection connection, string sql, params (string Name, object? Value)[] parameters)
    {
        object? result = await QueryScalarAsync(connection, sql, parameters);
        result.ShouldNotBeNull();
        return (byte[])result;
    }

    private static async Task<DateTimeOffset> QueryDateTimeOffsetAsync(NpgsqlConnection connection, string sql, params (string Name, object? Value)[] parameters)
    {
        object? result = await QueryScalarAsync(connection, sql, parameters);
        result.ShouldNotBeNull();
        return result switch
        {
            DateTimeOffset dateTimeOffset => dateTimeOffset,
            DateTime dateTime => new DateTimeOffset(DateTime.SpecifyKind(dateTime, DateTimeKind.Utc)),
            _ => throw new InvalidCastException($"Expected DateTimeOffset-compatible value but received {result.GetType().FullName}.")
        };
    }

    private static async Task<string?> QueryStringAsync(NpgsqlConnection connection, string sql, params (string Name, object? Value)[] parameters)
    {
        object? result = await QueryScalarAsync(connection, sql, parameters);
        return result as string;
    }

    private static async Task<short[]> QueryShortArrayAsync(NpgsqlConnection connection, string sql, params (string Name, object? Value)[] parameters)
    {
        object? result = await QueryScalarAsync(connection, sql, parameters);
        result.ShouldNotBeNull();
        return (short[])result;
    }

    private static async Task<object?> QueryScalarAsync(NpgsqlConnection connection, string sql, params (string Name, object? Value)[] parameters)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        AddParameters(command, parameters);
        object? result = await command.ExecuteScalarAsync();
        return result is DBNull ? null : result;
    }

    private static async Task<(short Status, string Code)> QueryShortStatusAsync(NpgsqlConnection connection, string sql, params (string Name, object? Value)[] parameters)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        AddParameters(command, parameters);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync();
        (await reader.ReadAsync()).ShouldBeTrue();
        return (Convert.ToInt16(reader.GetValue(0)), reader.GetString(1));
    }

    private static async Task<(bool Result, string Code)> QueryBoolStatusAsync(NpgsqlConnection connection, string sql, params (string Name, object? Value)[] parameters)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        AddParameters(command, parameters);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync();
        (await reader.ReadAsync()).ShouldBeTrue();
        return (reader.GetBoolean(0), reader.GetString(1));
    }


    private static async Task<(bool Result, string Code, short Attempts)> QueryBoolStatusAttemptsAsync(NpgsqlConnection connection, string sql, params (string Name, object? Value)[] parameters)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        AddParameters(command, parameters);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync();
        (await reader.ReadAsync()).ShouldBeTrue();
        return (reader.GetBoolean(0), reader.GetString(1), reader.GetInt16(2));
    }

    private static async Task<(bool Result, string Code, int Count)> QueryBoolStatusCountAsync(NpgsqlConnection connection, string sql, params (string Name, object? Value)[] parameters)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        AddParameters(command, parameters);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync();
        (await reader.ReadAsync()).ShouldBeTrue();
        return (reader.GetBoolean(0), reader.GetString(1), reader.GetInt32(2));
    }


    private static async Task<(bool Result, string Code, Guid? AccountSecurityStamp)> QueryLogoutAllStatusAsync(NpgsqlConnection connection, string sql, params (string Name, object? Value)[] parameters)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        AddParameters(command, parameters);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync();
        (await reader.ReadAsync()).ShouldBeTrue();
        return (reader.GetBoolean(0), reader.GetString(1), reader.IsDBNull(2) ? null : reader.GetGuid(2));
    }

    private static async Task<(short Status, string Code, DateTimeOffset? AccessExpiration, DateTimeOffset? SessionExpiration, DateTimeOffset? CutOff, Guid? SecurityStamp, Guid? AccountSecurityStamp)> QueryTrustStateAsync(NpgsqlConnection connection, string sql, params (string Name, object? Value)[] parameters)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        AddParameters(command, parameters);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync();
        (await reader.ReadAsync()).ShouldBeTrue();

        return (
            Convert.ToInt16(reader.GetValue(0)),
            reader.GetString(1),
            reader.IsDBNull(2) ? null : reader.GetFieldValue<DateTimeOffset>(2),
            reader.IsDBNull(3) ? null : reader.GetFieldValue<DateTimeOffset>(3),
            reader.IsDBNull(4) ? null : reader.GetFieldValue<DateTimeOffset>(4),
            reader.IsDBNull(5) ? null : reader.GetGuid(5),
            reader.IsDBNull(6) ? null : reader.GetGuid(6));
    }

    private sealed record AccountViewContractResult(
        bool Result,
        string Code,
        string? EmailAddress,
        string? Username,
        bool TwoFactorEnabled,
        short TwoFactorConfiguration,
        short[] TwoFactorMethods);

    private static async Task<AccountViewContractResult> QueryAccountViewAsync(NpgsqlConnection connection, string sql, params (string Name, object? Value)[] parameters)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        AddParameters(command, parameters);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync();
        (await reader.ReadAsync()).ShouldBeTrue();

        return new AccountViewContractResult(
            reader.GetBoolean(0),
            reader.GetString(1),
            reader.IsDBNull(2) ? null : reader.GetString(2),
            reader.IsDBNull(3) ? null : reader.GetString(3),
            !reader.IsDBNull(8) && reader.GetBoolean(8),
            reader.FieldCount > 9 && !reader.IsDBNull(9) ? reader.GetInt16(9) : (short)0,
            reader.FieldCount > 10 && !reader.IsDBNull(10) ? reader.GetFieldValue<short[]>(10) : []);
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
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "treehammock.csproj")))
        {
            directory = directory.Parent;
        }

        directory.ShouldNotBeNull();
        return Path.Combine(directory.FullName, "Rigging", "Database", "Baseline", "000_treehammock_canonical_database.sql");
    }
}
