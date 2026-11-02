using System.Security.Cryptography;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NodaTime;
using Npgsql;
using Shouldly;
using treehammock.DataLayer.Security;
using treehammock.Repos;
using treehammock.Rigging.Config;
using treehammock.Rigging.Operations;
using treehammock.Rigging.Security;
using treehammock.RiggingSupport.Enum;
using treehammock.Services;
using treehammock.Tests.SqlContracts.Support;

namespace treehammock.Tests.Integration.Database;

// Real service/repository/PostgreSQL and independent durable observers.
// COR16 SeedGrant substitutes completed password/factor attestation only.
[Trait("Suite", "SqlContracts")]
public sealed class Cor23AFAuthenticatorReplacementTests
{
    private sealed record Subject(Guid Account, Guid Stamp);
    private static Cor09RefreshHttpTests.FixtureStorage Storage(SqlContractFixture f) => new(f,
        new SecurityOperationSettings { HmacKeys = new() { [1] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)) } });
    private static async Task<T> Invoke<T>(Func<Task<T>> action)
    { using var scope = SecurityOperationRequestContext.Push(SecurityOperationRequestContext.Isolated("cor23af")); return await action(); }
    private static async Task Exec(NpgsqlConnection c, string sql, CancellationToken ct)
    { await using var command = new NpgsqlCommand(sql, c); await command.ExecuteNonQueryAsync(ct); }
    private static async Task<T> Scalar<T>(NpgsqlConnection c, string sql, CancellationToken ct)
    { await using var command = new NpgsqlCommand(sql, c); return (T)(await command.ExecuteScalarAsync(ct))!; }
    private static async Task<Subject> Seed(NpgsqlConnection c, CancellationToken ct)
    {
        (await Scalar<string>(c, "show plpgsql.variable_conflict", ct)).ShouldBe("error");
        var a = new Subject(Guid.NewGuid(), Guid.NewGuid());
        await Exec(c, $"insert into accounts(account_id,email_address,verify_status,security_stamp) values('{a.Account}','{a.Account:N}@example.test',1,'{a.Stamp}')", ct);
        return a;
    }
    private static TotpSettings Settings() => new() { ActiveProtectionKeyId = "replacement-test",
        ProtectionKeys = new() { ["replacement-test"] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)) } };
    private static async Task<SensitiveActionGrant> Grant(NpgsqlConnection c, Subject a, string canonical, CancellationToken ct, int purpose = 1)
    {
        var seeded = await Cor16EnrollmentSql.SeedGrant(c, a.Account, a.Stamp, purpose, ct);
        string target = SensitiveActionTargets.Hash(SensitiveActionPurpose.TWO_FACTOR_AUTHENTICATOR_SETUP, canonical,
            Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));
        await using var command = new NpgsqlCommand("""
            update sensitive_action_proof_sessions set target_hash=@target where handle_hash=@token;
            update sensitive_action_grants set target_hash=@target where token_hash=@token;
            """, c);
        command.Parameters.AddWithValue("target", target); command.Parameters.AddWithValue("token", seeded.Token);
        await command.ExecuteNonQueryAsync(ct);
        return new(seeded.Session, seeded.Token, target, canonical);
    }
    private static async Task<string> Snapshot(NpgsqlConnection c, Subject a, CancellationToken ct) =>
        await Scalar<string>(c, $"select coalesce(jsonb_agg(to_jsonb(t) order by t.two_factor_index),'[]'::jsonb)::text from two_factor_authentications t where t.account_id='{a.Account}'", ct);
    private static async Task AssertConsumed(NpgsqlConnection c, SensitiveActionGrant grant, bool consumed, CancellationToken ct) =>
        (await Scalar<bool>(c, $"select consumed_on is not null from sensitive_action_grants where token_hash='{grant.TokenHash}'", ct)).ShouldBe(consumed);
    private static BeginAuthenticatorAppSetupCommand Command(Subject a, SensitiveActionGrant grant, ProtectedTotpSecret secret,
        Guid? predecessor = null, long? version = null)
    {
        Instant now = Instant.FromUnixTimeMilliseconds(SystemClock.Instance.GetCurrentInstant().ToUnixTimeMilliseconds());
        return new(a.Account, a.Stamp, AccountVerificationTokenUtility.HashToken(AccountVerificationTokenUtility.GenerateToken()), now, now + Duration.FromMinutes(20), "phone", true,
            TotpProviderType.LOCAL_RFC6238, secret.Ciphertext, secret.Nonce, secret.Tag, secret.Version, grant,
            secret.KeyId, secret.Context, predecessor, version);
    }
    private static ProtectedTotpSecret Protect(TotpSecretProtector protector, Subject a, byte[] plain) =>
        protector.Protect(plain, new(a.Account, Guid.NewGuid(), new("SHA1", 6, 30, 1)));
    private static string Target(Guid? predecessor = null, long? version = null) =>
        SensitiveActionTargets.AuthenticatorSetup("phone", true, TotpProviderType.LOCAL_RFC6238, predecessor, version);
    private static async Task AssertMaterial(NpgsqlConnection observer, Subject a, TotpSecretProtector protector, TotpEnrollmentContext context,
        long version, string tokenHash, CancellationToken ct, byte[]? expectedPlain = null, string? manualKey = null)
    {
        await using var command = new NpgsqlCommand($"select totp_secret_ciphertext,totp_secret_nonce,totp_secret_tag,totp_secret_version,totp_key_id,totp_enrollment_id,setup_request_id,setup_version,token,two_factor_index,verified,totp_algorithm,totp_digits,totp_period_seconds,totp_clock_skew_steps from two_factor_authentications where account_id='{a.Account}' and revoked_at is null", observer);
        await using var reader = await command.ExecuteReaderAsync(ct);
        (await reader.ReadAsync(ct)).ShouldBeTrue();
        var persistedContext = new TotpEnrollmentContext(a.Account, reader.GetGuid(5),
            new(reader.GetString(11), reader.GetInt32(12), reader.GetInt32(13), reader.GetInt32(14)));
        persistedContext.ShouldBe(context);
        var stored = new ProtectedTotpSecret(reader.GetFieldValue<byte[]>(0), reader.GetFieldValue<byte[]>(1), reader.GetFieldValue<byte[]>(2), reader.GetInt32(3), reader.GetString(4), persistedContext);
        stored.Version.ShouldBe(TotpSecretProtector.CurrentVersion);
        byte[] plain = protector.Unprotect(stored);
        try
        {
            if (expectedPlain is not null) plain.ShouldBe(expectedPlain);
            if (manualKey is not null) new AuthenticatorAppBase32Encoder().Encode(plain).ShouldBe(manualKey);
        }
        finally { CryptographicOperations.ZeroMemory(plain); }
        reader.GetGuid(5).ShouldBe(context.EnrollmentId); reader.GetGuid(6).ShouldBe(context.EnrollmentId);
        reader.GetInt64(7).ShouldBe(version); reader.GetString(8).ShouldBe(tokenHash);
        reader.GetInt64(9).ShouldBe(0L); reader.GetBoolean(10).ShouldBeFalse();
        (await reader.ReadAsync(ct)).ShouldBeFalse();
    }

    [Fact]
    public void Canonical_targets_preserve_five_fields_and_label_normalization()
    {
        Guid id = Guid.NewGuid();
        using var fresh = System.Text.Json.JsonDocument.Parse(Target()["setup:".Length..]);
        fresh.RootElement.GetArrayLength().ShouldBe(5);
        fresh.RootElement[3].ValueKind.ShouldBe(System.Text.Json.JsonValueKind.Null);
        fresh.RootElement[4].ValueKind.ShouldBe(System.Text.Json.JsonValueKind.Null);
        using var replacement = System.Text.Json.JsonDocument.Parse(Target(id, 7)["setup:".Length..]);
        replacement.RootElement[3].GetGuid().ShouldBe(id); replacement.RootElement[4].GetInt64().ShouldBe(7L);
        SensitiveActionTargets.AuthenticatorSetup("  phone  ", true, TotpProviderType.LOCAL_RFC6238, id, 7).ShouldBe(Target(id, 7));
    }

    [Fact]
    public Task Fresh_null_predecessor_commits_enrollment_bound_v2_material() => SqlContractFixture.RunAsync(async (f, ct) =>
    {
        var writer = await f.OpenConnectionAsync(); var observer = await f.OpenConnectionAsync(); var a = await Seed(writer, ct);
        var protector = new TotpSecretProtector(Options.Create(Settings())); byte[] plain = RandomNumberGenerator.GetBytes(20);
        var secret = Protect(protector, a, plain); var grant = await Grant(writer, a, Target(), ct);
        var command = Command(a, grant, secret); command.ExpectedEnrollmentId.ShouldBeNull(); command.ExpectedVersion.ShouldBeNull();
        await using var storage = Storage(f); var repo = new AuthenticatorAppEnrollmentRepo(storage, NullLogger<AuthenticatorAppEnrollmentRepo>.Instance);
        var result = (await Invoke(() => repo.BeginAuthenticatorAppSetupAsync(command, ct))).ShouldNotBeNull();
        result.Result.ShouldBeTrue(); result.Code.ShouldBe("AUTHENTICATOR_SETUP_PENDING"); result.TwoFactorIndex.ShouldBe(0L);
        await AssertMaterial(observer, a, protector, secret.Context, 1, command.SetupTokenHash, ct, plain);
        await AssertConsumed(observer, grant, true, ct); CryptographicOperations.ZeroMemory(plain);
    });

    [Fact]
    public Task Actual_repository_replacement_with_predecessor_bound_grant_commits() => SqlContractFixture.RunAsync(async (f, ct) =>
    {
        var writer = await f.OpenConnectionAsync(); var observer = await f.OpenConnectionAsync(); var a = await Seed(writer, ct);
        var protector = new TotpSecretProtector(Options.Create(Settings())); byte[] plain = RandomNumberGenerator.GetBytes(20);
        var first = Protect(protector, a, plain); var initialGrant = await Grant(writer, a, Target(), ct);
        await using var storage = Storage(f); var repo = new AuthenticatorAppEnrollmentRepo(storage, NullLogger<AuthenticatorAppEnrollmentRepo>.Instance);
        (await Invoke(() => repo.BeginAuthenticatorAppSetupAsync(Command(a, initialGrant, first), ct))).ShouldNotBeNull().Result.ShouldBeTrue();
        string before = await Snapshot(observer, a, ct);
        var replacement = Protect(protector, a, plain); var grant = await Grant(writer, a, Target(first.Context.EnrollmentId, 1), ct);
        var command = Command(a, grant, replacement, first.Context.EnrollmentId, 1);
        var result = (await Invoke(() => repo.BeginAuthenticatorAppSetupAsync(command, ct))).ShouldNotBeNull();
        result.Result.ShouldBeTrue(); result.Code.ShouldBe("AUTHENTICATOR_SETUP_PENDING"); result.TwoFactorIndex.ShouldBe(0L);
        result.Expiration.ShouldBe(command.Expiration); (await Snapshot(observer, a, ct)).ShouldNotBe(before);
        await AssertMaterial(observer, a, protector, replacement.Context, 2, command.SetupTokenHash, ct, plain);
        await AssertConsumed(observer, grant, true, ct);
        (await Scalar<long>(observer, $"select count(*) from two_factor_authentications where account_id='{a.Account}' and setup_request_id='{first.Context.EnrollmentId}'", ct)).ShouldBe(0L);
        CryptographicOperations.ZeroMemory(plain);
    });

    [Theory]
    [InlineData("stale-identity", "AUTHENTICATOR_SETUP_CONFLICT")]
    [InlineData("stale-version", "AUTHENTICATOR_SETUP_CONFLICT")]
    [InlineData("other-predecessor", "SENSITIVE_ACTION_GRANT_REQUIRED")]
    [InlineData("label", "SENSITIVE_ACTION_GRANT_REQUIRED")]
    [InlineData("required", "SENSITIVE_ACTION_GRANT_REQUIRED")]
    [InlineData("provider", "SENSITIVE_ACTION_GRANT_REQUIRED")]
    [InlineData("missing", "SENSITIVE_ACTION_GRANT_REQUIRED")]
    [InlineData("stamp", "SENSITIVE_ACTION_GRANT_REQUIRED")]
    [InlineData("session", "SENSITIVE_ACTION_GRANT_REQUIRED")]
    [InlineData("target-hash", "SENSITIVE_ACTION_GRANT_REQUIRED")]
    [InlineData("purpose", "SENSITIVE_ACTION_GRANT_REQUIRED")]
    [InlineData("token", "SENSITIVE_ACTION_GRANT_REQUIRED")]
    [InlineData("account", "SENSITIVE_ACTION_GRANT_REQUIRED")]
    public Task Stale_or_mismatched_target_preserves_original_setup(string invalid, string code) => SqlContractFixture.RunAsync(async (f, ct) =>
    {
        var writer = await f.OpenConnectionAsync(); var observer = await f.OpenConnectionAsync(); var a = await Seed(writer, ct);
        var protector = new TotpSecretProtector(Options.Create(Settings())); byte[] plain = RandomNumberGenerator.GetBytes(20);
        var first = Protect(protector, a, plain); var initial = await Grant(writer, a, Target(), ct);
        await using var storage = Storage(f); var repo = new AuthenticatorAppEnrollmentRepo(storage, NullLogger<AuthenticatorAppEnrollmentRepo>.Instance);
        (await Invoke(() => repo.BeginAuthenticatorAppSetupAsync(Command(a, initial, first), ct))).ShouldNotBeNull().Result.ShouldBeTrue();
        string before = await Snapshot(observer, a, ct);
        Guid predecessor = invalid == "stale-identity" ? Guid.NewGuid() : first.Context.EnrollmentId;
        long version = invalid == "stale-version" ? 99L : 1L;
        var grant = await Grant(writer, a, Target(invalid == "other-predecessor" ? Guid.NewGuid() : predecessor, version), ct, invalid == "purpose" ? 3 : 1);
        Subject subject = invalid == "account" ? await Seed(writer, ct) : a;
        var command = Command(subject, grant, Protect(protector, subject, plain), predecessor, version);
        command = invalid switch
        {
            "label" => command with { AuthId = "another-phone" },
            "required" => command with { Required = false },
            "provider" => command with { TotpProviderType = TotpProviderType.TWILIO_VERIFY_TOTP },
            "missing" => command with { Grant = null },
            "stamp" => command with { AccountSecurityStamp = Guid.NewGuid() },
            "session" => command with { Grant = grant with { SessionHash = "different-session" } },
            "target-hash" => command with { Grant = grant with { TargetHash = new string('b', 64) } },
            "token" => command with { Grant = grant with { TokenHash = new string('f', 64) } },
            _ => command
        };
        var result = (await Invoke(() => repo.BeginAuthenticatorAppSetupAsync(command, ct))).ShouldNotBeNull();
        result.Result.ShouldBeFalse(); result.Code.ShouldBe(code); result.TwoFactorIndex.ShouldBeNull(); result.Expiration.ShouldBeNull();
        (await Snapshot(observer, a, ct)).ShouldBe(before); await AssertConsumed(observer, grant, false, ct);
        if (invalid == "account") (await Snapshot(observer, subject, ct)).ShouldBe("[]");
        CryptographicOperations.ZeroMemory(plain);
    });

    [Fact]
    public Task Actual_service_and_repository_agree_on_fresh_and_replacement_targets() => SqlContractFixture.RunAsync(async (f, ct) =>
    {
        var writer = await f.OpenConnectionAsync(); var observer = await f.OpenConnectionAsync(); var a = await Seed(writer, ct);
        var settings = Settings(); var options = Options.Create(settings); var protector = new TotpSecretProtector(options);
        await using var storage = Storage(f); var repo = new AuthenticatorAppEnrollmentRepo(storage, NullLogger<AuthenticatorAppEnrollmentRepo>.Instance);
        var provider = new LocalTotpProvider(new AuthenticatorAppSecretGenerator(options), new AuthenticatorAppBase32Encoder(), new AuthenticatorAppProvisioningUriBuilder(options), options);
        var service = new AuthenticatorAppSetupService(repo, new TotpProviderRegistry([provider]), protector, new TotpCodeVerifier(), options, NullLogger<AuthenticatorAppSetupService>.Instance);
        var firstGrant = await Grant(writer, a, Target(), ct);
        var first = await Invoke(() => service.StartSetupAsync(new(a.Account, a.Stamp, $"{a.Account:N}@example.test", "  phone  ", true, Grant: firstGrant), ct));
        first.Succeeded.ShouldBeTrue(); first.SetupVersion.ShouldBe(1L); first.EnrollmentId.ShouldNotBeNull();
        var grant = await Grant(writer, a, Target(first.EnrollmentId, first.SetupVersion), ct);
        var replaced = await Invoke(() => service.StartSetupAsync(new(a.Account, a.Stamp, $"{a.Account:N}@example.test", "phone", true,
            Grant: grant, ExpectedEnrollmentId: first.EnrollmentId, ExpectedVersion: first.SetupVersion), ct));
        replaced.Succeeded.ShouldBeTrue(); replaced.SetupVersion.ShouldBe(2L); replaced.EnrollmentId.ShouldNotBe(first.EnrollmentId);
        replaced.SetupId.ShouldNotBeNullOrWhiteSpace(); replaced.ManualEntryKey.ShouldNotBeNullOrWhiteSpace();
        var context = new TotpEnrollmentContext(a.Account, replaced.EnrollmentId!.Value, TotpParameters.FromDefaults(settings));
        await AssertMaterial(observer, a, protector, context, 2, AccountVerificationTokenUtility.HashToken(replaced.SetupId!), ct, manualKey: replaced.ManualEntryKey);
        await AssertConsumed(observer, firstGrant, true, ct); await AssertConsumed(observer, grant, true, ct);
    });

    [Fact]
    public Task Verified_enrollment_remains_unchanged_when_replacement_is_denied() => SqlContractFixture.RunAsync(async (f, ct) =>
    {
        var writer = await f.OpenConnectionAsync(); var observer = await f.OpenConnectionAsync(); var a = await Seed(writer, ct);
        var protector = new TotpSecretProtector(Options.Create(Settings())); byte[] plain = RandomNumberGenerator.GetBytes(20);
        var first = Protect(protector, a, plain); var initial = await Grant(writer, a, Target(), ct);
        await using var storage = Storage(f); var repo = new AuthenticatorAppEnrollmentRepo(storage, NullLogger<AuthenticatorAppEnrollmentRepo>.Instance);
        (await Invoke(() => repo.BeginAuthenticatorAppSetupAsync(Command(a, initial, first), ct))).ShouldNotBeNull().Result.ShouldBeTrue();
        await Exec(writer, $"update two_factor_authentications set verified=true where account_id='{a.Account}'", ct);
        string before = await Snapshot(observer, a, ct); var grant = await Grant(writer, a, Target(first.Context.EnrollmentId, 1), ct);
        var result = (await Invoke(() => repo.BeginAuthenticatorAppSetupAsync(Command(a, grant, Protect(protector, a, plain), first.Context.EnrollmentId, 1), ct))).ShouldNotBeNull();
        result.Result.ShouldBeFalse(); result.Code.ShouldBe("TWO_FACTOR_AUTHENTICATOR_APP_ALREADY_ATTACHED");
        (await Snapshot(observer, a, ct)).ShouldBe(before);
        // Existing SQL consumes an authorized grant before its already-attached return.
        await AssertConsumed(observer, grant, true, ct);
        CryptographicOperations.ZeroMemory(plain);
    });
}
