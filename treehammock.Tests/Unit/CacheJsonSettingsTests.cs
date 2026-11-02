using System.ComponentModel.DataAnnotations;
using Microsoft.Extensions.Options;
using NodaTime;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using NSubstitute;
using Shouldly;
using StackExchange.Redis;

using treehammock.DataLayer.Cache;
using treehammock.Rigging.Cache;
using treehammock.Rigging.Config;
using treehammock.RiggingSupport.Enum;

namespace treehammock.Tests.Unit;

public class CacheJsonSettingsTests
{
    [Fact]
    public void ActiveSession_round_trips_new_cache_contract_fields()
    {
        var session = BuildActiveSession();

        string json = CacheJsonSettings.Serialize(session);
        var roundTrip = CacheJsonSettings.Deserialize<ActiveSession>(json);

        roundTrip.ShouldNotBeNull();
        roundTrip.accountId.ShouldBe(session.accountId);
        roundTrip.refreshToken.ShouldBe(session.refreshToken);
        roundTrip.refreshes.ShouldBe(session.refreshes);
        roundTrip.familyId.ShouldBe(session.familyId);
        roundTrip.generation.ShouldBe(session.generation);
        roundTrip.protocolVersion.ShouldBe(2);
        roundTrip.createdOn.ShouldBe(session.createdOn);
        roundTrip.sessionLifespan.ShouldBe(session.sessionLifespan);
        roundTrip.accessExpiration.ShouldBe(session.accessExpiration);
        roundTrip.sessionExpiration.ShouldBe(session.sessionExpiration);
        roundTrip.cutOff.ShouldBe(session.cutOff);
        roundTrip.features.ShouldBe(session.features);
        roundTrip.securityStamp.ShouldBe(session.securityStamp);
        roundTrip.accountSecurityStamp.ShouldBe(session.accountSecurityStamp);
    }

    [Fact]
    public void ActiveSession_serializes_only_new_expiration_and_lifespan_contract_keys()
    {
        string json = CacheJsonSettings.Serialize(BuildActiveSession());
        var payload = JObject.Parse(json);

        payload.Property("sessionLifespan").ShouldNotBeNull();
        payload.Property("accessExpiration").ShouldNotBeNull();
        payload.Property("sessionExpiration").ShouldNotBeNull();
        payload.Property("lifespan").ShouldBeNull();
        payload.Property("expiration").ShouldBeNull();
        payload.Property("securityStamp").ShouldNotBeNull();
        payload.Property("accountSecurityStamp").ShouldNotBeNull();
        payload.Property("EffectiveSessionExpiration").ShouldBeNull();
    }

    [Theory]
    [InlineData("accessExpiration")]
    [InlineData("sessionLifespan")]
    [InlineData("sessionExpiration")]
    [InlineData("securityStamp")]
    [InlineData("accountSecurityStamp")]
    [InlineData("familyId")]
    [InlineData("generation")]
    [InlineData("protocolVersion")]
    [InlineData("entitlements")]
    public void ActiveSession_requires_new_cache_contract_fields(string requiredField)
    {
        var payload = JObject.Parse(ActiveSessionGoldenJson());
        payload.Remove(requiredField);

        Exception exception = Should.Throw<Exception>(() =>
            CacheJsonSettings.Deserialize<ActiveSession>(payload.ToString(Formatting.None)));

        // These constructor guards reject absent/default authority fields before
        // Newtonsoft can finish its Required-property validation.
        if (requiredField is "accountSecurityStamp" or "generation" or "protocolVersion")
        {
            exception.ShouldBeOfType<ArgumentException>();
        }
        else
        {
            exception.ShouldBeOfType<JsonSerializationException>();
        }
    }

    [Fact]
    public void ActiveSession_golden_json_payload_is_stable()
    {
        string json = CacheJsonSettings.Serialize(BuildActiveSession());
        var actual = JObject.Parse(json);
        var expected = JObject.Parse(ActiveSessionGoldenJson());

        actual.Properties().Select(property => property.Name).ShouldBe(expected.Properties().Select(property => property.Name));
        JToken.DeepEquals(actual, expected).ShouldBeTrue(json);
    }

    [Fact]
    public void ActiveSession_toSession_uses_hard_session_expiration()
    {
        var session = BuildActiveSession();

        var stored = session.toSession();

        stored.accessExpiration.ShouldBe(session.accessExpiration);
        stored.sessionExpiration.ShouldBe(session.sessionExpiration);
        stored.sessionExpiration.ShouldNotBe(session.accessExpiration);
        stored.sessionLifespan.ShouldBe(session.sessionLifespan);
        stored.securityStamp.ShouldBe(session.securityStamp);
        stored.accountSecurityStamp.ShouldBe(session.accountSecurityStamp);
    }

    [Fact]
    public void TwoFactorSession_round_trips_noda_time_challenge_state_and_destination_metadata()
    {
        var session = BuildTwoFactorSession();

        string json = CacheJsonSettings.Serialize(session);
        var roundTrip = CacheJsonSettings.Deserialize<TwoFactorSession>(json);

        roundTrip.ShouldNotBeNull();
        roundTrip.accountId.ShouldBe(session.accountId);
        roundTrip.webKey.ShouldBe(session.webKey);
        roundTrip.preAuthRefreshToken.ShouldBe(session.preAuthRefreshToken);
        roundTrip.methods.ShouldBe(session.methods);
        roundTrip.userAuthIds.ShouldBe(session.userAuthIds);
        roundTrip.phoneNumbers.ShouldBe(session.phoneNumbers);
        roundTrip.phoneCountryCode.ShouldBe(session.phoneCountryCode);
        roundTrip.emailAddresses.ShouldBe(session.emailAddresses);
        roundTrip.chosenDestination.ShouldBe(session.chosenDestination);
        roundTrip.intraCodeKey.ShouldBe(session.intraCodeKey);
        roundTrip.challengedMethod.ShouldBe(session.challengedMethod);
        roundTrip.challengeCodeHash.ShouldBe(session.challengeCodeHash);
        roundTrip.challengeExpiration.ShouldBe(session.challengeExpiration);
        roundTrip.challengeProviderTransactionId.ShouldBe(session.challengeProviderTransactionId);
        roundTrip.challengeAttempts.ShouldBe(session.challengeAttempts);
        roundTrip.challengeResends.ShouldBe(session.challengeResends);
        roundTrip.nextChallengeAllowedAt.ShouldBe(session.nextChallengeAllowedAt);
        roundTrip.authenticatorAppUsage.ShouldBe(session.authenticatorAppUsage);
        roundTrip.smsKeyUsage.ShouldBe(session.smsKeyUsage);
        roundTrip.smsUsage.ShouldBe(session.smsUsage);
        roundTrip.createdOn.ShouldBe(session.createdOn);
        roundTrip.expiration.ShouldBe(session.expiration);
        roundTrip.cutOff.ShouldBe(session.cutOff);
        roundTrip.features.ShouldBe(session.features);
        roundTrip.accountSecurityStamp.ShouldBe(session.accountSecurityStamp);
        roundTrip.availableConfigurationsSnapshot.ShouldBe(session.availableConfigurationsSnapshot);
        roundTrip.selectedConfiguration.ShouldBe(session.selectedConfiguration);
        roundTrip.state.ShouldBe(session.state);
        roundTrip.requiredMethods.ShouldBe(session.requiredMethods);
        roundTrip.completedMethods.ShouldBe(session.completedMethods);
        roundTrip.currentExpectedMethod.ShouldBe(session.currentExpectedMethod);
        roundTrip.progressVersion.ShouldBe(session.progressVersion);
        roundTrip.challengeId.ShouldBe(session.challengeId);
        roundTrip.remainingMethods.ShouldBe(session.remainingMethods);
        roundTrip.requiredProofCount.ShouldBe(session.requiredProofCount);
        roundTrip.completedProofCount.ShouldBe(session.completedProofCount);
    }

    [Fact]
    public void TwoFactorSession_golden_json_payload_is_stable()
    {
        string json = CacheJsonSettings.Serialize(BuildTwoFactorSession());
        var actual = JObject.Parse(json);
        var expected = JObject.Parse(TwoFactorSessionGoldenJson());

        actual.Properties().Select(property => property.Name).ShouldBe(expected.Properties().Select(property => property.Name));
        actual.Property("remainingMethods").ShouldBeNull();
        actual.Property("requiredProofCount").ShouldBeNull();
        actual.Property("completedProofCount").ShouldBeNull();
        actual.Property("isSelectionRequired").ShouldBeNull();
        actual.Property("isComplete").ShouldBeNull();
        JToken.DeepEquals(actual, expected).ShouldBeTrue(json);
    }

    [Theory]
    [InlineData("progressVersion")] [InlineData("challengeId")]
    public void Pending_proof_payload_requires_current_lineage_fields(string field)
    {
        var json=Newtonsoft.Json.Linq.JObject.Parse(CacheJsonSettings.Serialize(BuildTwoFactorSession()));json.Remove(field);
        Should.Throw<Newtonsoft.Json.JsonSerializationException>(()=>CacheJsonSettings.Deserialize<TwoFactorSession>(json.ToString()));
    }

    [Fact]
    public void TwoFactorSession_missing_account_security_stamp_is_rejected_as_legacy_payload()
    {
        var payload = JObject.Parse(TwoFactorSessionGoldenJson());
        payload.Remove("accountSecurityStamp");

        Should.Throw<ArgumentException>(() =>
            CacheJsonSettings.Deserialize<TwoFactorSession>(payload.ToString(Formatting.None)));
    }


    [Fact]
    public async Task TwoFactor_get_session_wraps_legacy_payload_as_stale_pending_cache_payload()
    {
        const string hash = "pending-token-hash";
        var payload = JObject.Parse(TwoFactorSessionGoldenJson());
        payload.Remove("accountSecurityStamp");
        var database = Substitute.For<IDatabase>();
        var connection = Substitute.For<IConnectionMultiplexer>();

        connection.GetDatabase(Arg.Any<int>(), Arg.Any<object?>()).Returns(database);
        database.StringGetAsync(Arg.Is<RedisKey>(key => key.ToString() == hash), Arg.Any<CommandFlags>())
            .Returns(Task.FromResult((RedisValue)payload.ToString(Formatting.None)));
        var service = new TwoFactorSessionService(Options.Create(TwoFactorSettings(database: 1)), connection);

        Exception? exception = null;
        try
        {
            _ = await service.GetSession(hash);
        }
        catch (Exception caught)
        {
            exception = caught;
        }

        var stalePayload = exception.ShouldBeOfType<StalePendingTwoFactorCachePayloadException>();
        stalePayload.InnerException.ShouldBeOfType<ArgumentException>();
    }

    [Fact]
    public async Task TwoFactor_get_session_wraps_malformed_json_as_stale_pending_cache_payload()
    {
        const string hash = "pending-token-hash";
        var database = Substitute.For<IDatabase>();
        var connection = Substitute.For<IConnectionMultiplexer>();

        connection.GetDatabase(Arg.Any<int>(), Arg.Any<object?>()).Returns(database);
        database.StringGetAsync(Arg.Is<RedisKey>(key => key.ToString() == hash), Arg.Any<CommandFlags>())
            .Returns(Task.FromResult((RedisValue)"{not-json"));
        var service = new TwoFactorSessionService(Options.Create(TwoFactorSettings(database: 1)), connection);

        Exception? exception = null;
        try
        {
            _ = await service.GetSession(hash);
        }
        catch (Exception caught)
        {
            exception = caught;
        }

        var stalePayload = exception.ShouldBeOfType<StalePendingTwoFactorCachePayloadException>();
        stalePayload.InnerException.ShouldBeOfType<JsonReaderException>();
    }

    [Fact]
    public async Task TwoFactor_get_session_preserves_cache_infrastructure_failures()
    {
        const string hash = "pending-token-hash";
        var database = Substitute.For<IDatabase>();
        var connection = Substitute.For<IConnectionMultiplexer>();
        var expected = new InvalidOperationException("redis read failed");

        connection.GetDatabase(Arg.Any<int>(), Arg.Any<object?>()).Returns(database);
        database.StringGetAsync(Arg.Is<RedisKey>(key => key.ToString() == hash), Arg.Any<CommandFlags>())
            .Returns(_ => Task.FromException<RedisValue>(expected));
        await using var service = new TwoFactorSessionService(Options.Create(TwoFactorSettings(database: 1)), connection);

        Exception? exception = null;
        try
        {
            _ = await service.GetSession(hash);
        }
        catch (Exception caught)
        {
            exception = caught;
        }

        var unavailable = exception.ShouldBeOfType<treehammock.Rigging.Dependencies.DependencyUnavailableException>();
        unavailable.InnerException.ShouldBeSameAs(expected);
        unavailable.Failure.Dependency.ShouldBe("dragonfly");
        unavailable.Failure.Operation.ShouldBe("cache_command");
        unavailable.Failure.Kind.ShouldBe(treehammock.Rigging.Dependencies.DependencyFailureKind.Unavailable);
        unavailable.Failure.Stage.ShouldBe(treehammock.Rigging.Dependencies.DependencyStage.Execute);
    }


    [Fact]
    public async Task ActiveUser_get_session_wraps_legacy_payload_as_stale_active_cache_payload()
    {
        const string hash = "active-token-hash";
        var payload = JObject.Parse(ActiveSessionGoldenJson());
        payload.Remove("accountSecurityStamp");
        var database = Substitute.For<IDatabase>();
        var connection = Substitute.For<IConnectionMultiplexer>();

        connection.GetDatabase(Arg.Any<int>(), Arg.Any<object?>()).Returns(database);
        database.StringGetAsync(Arg.Is<RedisKey>(key => key.ToString() == hash), Arg.Any<CommandFlags>())
            .Returns(Task.FromResult((RedisValue)payload.ToString(Formatting.None)));
        var service = new ActiveUserCacheService(Options.Create(ActiveUserSettings(database: 0)), connection);

        Exception? exception = null;
        try
        {
            _ = await service.GetSession(hash);
        }
        catch (Exception caught)
        {
            exception = caught;
        }

        var stalePayload = exception.ShouldBeOfType<StaleActiveSessionCachePayloadException>();
        stalePayload.InnerException.ShouldBeOfType<ArgumentException>();
    }

    [Fact]
    public async Task ActiveUser_get_session_wraps_malformed_json_as_stale_active_cache_payload()
    {
        const string hash = "active-token-hash";
        var database = Substitute.For<IDatabase>();
        var connection = Substitute.For<IConnectionMultiplexer>();

        connection.GetDatabase(Arg.Any<int>(), Arg.Any<object?>()).Returns(database);
        database.StringGetAsync(Arg.Is<RedisKey>(key => key.ToString() == hash), Arg.Any<CommandFlags>())
            .Returns(Task.FromResult((RedisValue)"{not-json"));
        var service = new ActiveUserCacheService(Options.Create(ActiveUserSettings(database: 0)), connection);

        Exception? exception = null;
        try
        {
            _ = await service.GetSession(hash);
        }
        catch (Exception caught)
        {
            exception = caught;
        }

        var stalePayload = exception.ShouldBeOfType<StaleActiveSessionCachePayloadException>();
        stalePayload.InnerException.ShouldBeOfType<JsonReaderException>();
    }

    [Fact]
    public async Task ActiveUser_get_session_preserves_cache_infrastructure_failures()
    {
        const string hash = "active-token-hash";
        var database = Substitute.For<IDatabase>();
        var connection = Substitute.For<IConnectionMultiplexer>();
        var expected = new InvalidOperationException("redis read failed");

        connection.GetDatabase(Arg.Any<int>(), Arg.Any<object?>()).Returns(database);
        database.StringGetAsync(Arg.Is<RedisKey>(key => key.ToString() == hash), Arg.Any<CommandFlags>())
            .Returns(_ => Task.FromException<RedisValue>(expected));
        await using var service = new ActiveUserCacheService(Options.Create(ActiveUserSettings(database: 0)), connection);

        Exception? exception = null;
        try
        {
            _ = await service.GetSession(hash);
        }
        catch (Exception caught)
        {
            exception = caught;
        }

        var unavailable = exception.ShouldBeOfType<treehammock.Rigging.Dependencies.DependencyUnavailableException>();
        unavailable.InnerException.ShouldBeSameAs(expected);
        unavailable.Failure.Dependency.ShouldBe("dragonfly");
        unavailable.Failure.Operation.ShouldBe("cache_command");
        unavailable.Failure.Kind.ShouldBe(treehammock.Rigging.Dependencies.DependencyFailureKind.Unavailable);
        unavailable.Failure.Stage.ShouldBe(treehammock.Rigging.Dependencies.DependencyStage.Execute);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task Caller_cancellation_is_not_a_cache_outage_and_does_not_dispatch(bool pending)
    {
        var database = Substitute.For<IDatabase>();
        var connection = Substitute.For<IConnectionMultiplexer>();
        connection.GetDatabase(Arg.Any<int>(), Arg.Any<object?>()).Returns(database);
        using var cancellation = new CancellationTokenSource(); cancellation.Cancel();
        if (pending)
        {
            await using var service = new TwoFactorSessionService(Options.Create(TwoFactorSettings(1)), connection);
            await Should.ThrowAsync<OperationCanceledException>(() => service.GetSession("cancelled", cancellation.Token));
        }
        else
        {
            await using var service = new ActiveUserCacheService(Options.Create(ActiveUserSettings(0)), connection);
            await Should.ThrowAsync<OperationCanceledException>(() => service.GetSession("cancelled", cancellation.Token));
        }
        _ = database.DidNotReceive().StringGetAsync(Arg.Any<RedisKey>(), Arg.Any<CommandFlags>());
    }

    [Fact]
    public void Active_and_two_factor_cache_configuration_use_separate_default_databases()
    {
        var active = new UserCacheSettings
        {
            servers = "localhost",
            port = 6379,
            database = 0,
            clientName = "treehammock-active",
            password = string.Empty
        };

        var twoFactor = new TwoFactorSessionCacheSettings
        {
            servers = "localhost",
            port = 6379,
            database = 1,
            clientName = "treehammock-2fa",
            password = string.Empty
        };

        ActiveUserCacheService.BuildConfiguration(active).DefaultDatabase.ShouldBe(0);
        TwoFactorSessionService.BuildConfiguration(twoFactor).DefaultDatabase.ShouldBe(1);
    }



    [Fact]
    public void Session_cache_fallback_settings_require_bounded_timeouts()
    {
        var settings = new SessionCacheFallbackSettings
        {
            CacheReadTimeoutMilliseconds = 0,
            CacheWriteTimeoutMilliseconds = 0,
            CacheRevokeTimeoutMilliseconds = 0,
            DatabaseFallbackTimeoutMilliseconds = 0
        };
        var results = new List<ValidationResult>();

        bool valid = Validator.TryValidateObject(settings, new ValidationContext(settings), results, validateAllProperties: true);

        valid.ShouldBeFalse();
        results.Count.ShouldBeGreaterThanOrEqualTo(4);
    }

    [Fact]
    public void Cache_configuration_applies_bounded_redis_timeout_settings()
    {
        var active = new UserCacheSettings
        {
            servers = "localhost",
            port = 6379,
            database = 0,
            clientName = "treehammock-active",
            password = string.Empty,
            connectTimeoutMilliseconds = 1234,
            asyncTimeoutMilliseconds = 2345,
            syncTimeoutMilliseconds = 3456,
            connectRetry = 2
        };

        ConfigurationOptions options = ActiveUserCacheService.BuildConfiguration(active);

        options.ConnectTimeout.ShouldBe(1234);
        options.AsyncTimeout.ShouldBe(2345);
        options.SyncTimeout.ShouldBe(3456);
        options.ConnectRetry.ShouldBe(2);
    }

    [Fact]
    public async Task TwoFactor_revoke_treats_missing_key_as_success()
    {
        const string hash = "pending-token-hash";
        var database = Substitute.For<IDatabase>();
        var connection = Substitute.For<IConnectionMultiplexer>();

        connection.GetDatabase(Arg.Any<int>(), Arg.Any<object?>()).Returns(database);
        database.KeyDeleteAsync(Arg.Is<RedisKey>(key => key.ToString() == hash), Arg.Any<CommandFlags>())
            .Returns(Task.FromResult(false));
        database.KeyExistsAsync(Arg.Is<RedisKey>(key => key.ToString() == hash), Arg.Any<CommandFlags>())
            .Returns(Task.FromResult(false));

        var service = new TwoFactorSessionService(Options.Create(TwoFactorSettings(database: 1)), connection);

        bool result = await service.RevokeSession(hash);

        result.ShouldBeTrue();
        await database.Received(1).KeyDeleteAsync(Arg.Is<RedisKey>(key => key.ToString() == hash), Arg.Any<CommandFlags>());
        await database.Received(1).KeyExistsAsync(Arg.Is<RedisKey>(key => key.ToString() == hash), Arg.Any<CommandFlags>());
    }

    [Fact]
    public async Task TwoFactor_revoke_returns_false_when_delete_fails_and_key_still_exists()
    {
        const string hash = "pending-token-hash";
        var database = Substitute.For<IDatabase>();
        var connection = Substitute.For<IConnectionMultiplexer>();

        connection.GetDatabase(Arg.Any<int>(), Arg.Any<object?>()).Returns(database);
        database.KeyDeleteAsync(Arg.Is<RedisKey>(key => key.ToString() == hash), Arg.Any<CommandFlags>())
            .Returns(Task.FromResult(false));
        database.KeyExistsAsync(Arg.Is<RedisKey>(key => key.ToString() == hash), Arg.Any<CommandFlags>())
            .Returns(Task.FromResult(true));

        var service = new TwoFactorSessionService(Options.Create(TwoFactorSettings(database: 1)), connection);

        bool result = await service.RevokeSession(hash);

        result.ShouldBeFalse();
    }

    private static ActiveSession BuildActiveSession()
    {
        return new ActiveSession(
            Guid.Parse("11111111-1111-1111-1111-111111111111"),
            new byte[] { 1, 2, 3, 4 },
            2,
            Instant.FromUtc(2026, 5, 16, 12, 0),
            Period.FromMinutes(90),
            Instant.FromUtc(2026, 5, 16, 12, 15),
            Instant.FromUtc(2026, 5, 16, 13, 30),
            null,
            FeatureSet.premium,
            Guid.Parse("33333333-3333-3333-3333-333333333333"),
            Guid.Parse("44444444-4444-4444-4444-444444444444"), entitlements: treehammock.Tests.Support.EntitlementTestData.ForAccount(Guid.Parse("11111111-1111-1111-1111-111111111111"), FeatureSet.premium, Instant.FromUtc(2026,5,16,12,0)));
    }

    private static string ActiveSessionGoldenJson()
    {
        return """
            {
              "accountId": "11111111-1111-1111-1111-111111111111",
              "refreshToken": "AQIDBA==",
              "refreshes": 2,
              "createdOn": "2026-05-16T12:00:00Z",
              "sessionLifespan": "PT90M",
              "accessExpiration": "2026-05-16T12:15:00Z",
              "sessionExpiration": "2026-05-16T13:30:00Z",
              "cutOff": null,
              "features": "premium",
              "securityStamp": "33333333-3333-3333-3333-333333333333",
              "accountSecurityStamp": "44444444-4444-4444-4444-444444444444",
              "familyId": "33333333-3333-3333-3333-333333333333",
              "generation": 1,
              "protocolVersion": 2,
              "entitlements": {
                "accountId": "11111111-1111-1111-1111-111111111111",
                "version": 1,
                "features": "premium",
                "capabilities": ["account.read", "account.manage"],
                "rightsEnabled": true,
                "evaluatedAt": "2026-05-16T12:00:00Z",
                "nextBoundary": null,
                "eligibilityUntil": null,
                "grants": []
              }
            }
            """;
    }

    private static TwoFactorSession BuildTwoFactorSession()
    {
        return new TwoFactorSession(
            Guid.Parse("22222222-2222-2222-2222-222222222222"),
            "web-key",
            new byte[] { 9, 8, 7, 6 },
            new List<TwoFactorAuthMethod> { TwoFactorAuthMethod.EMAIL, TwoFactorAuthMethod.SMS_KEY },
            new List<string> { "authenticator-app-user" },
            new List<string> { "4045550100" },
            new List<string> { "1" },
            new List<string> { "reader@example.com" },
            1,
            "intra-key",
            3,
            4,
            5,
            Instant.FromUtc(2026, 5, 16, 12, 0),
            Instant.FromUtc(2026, 5, 16, 12, 5),
            FeatureSet.rawrzilla,
            Instant.FromUtc(2026, 5, 18, 0, 0),
            Guid.Parse("55555555-5555-5555-5555-555555555555"))
        {
            challengedMethod = TwoFactorAuthMethod.SMS_KEY,
            challengeCodeHash = "challenge-hash",
            challengeExpiration = Instant.FromUtc(2026, 5, 16, 12, 3),
            challengeProviderTransactionId = "provider-transaction",
            challengeAttempts = 1,
            challengeResends = 2,
            nextChallengeAllowedAt = Instant.FromUtc(2026, 5, 16, 12, 1),
            selectedConfiguration = TwoFactorAuthConfiguration.SMS,
            state = TwoFactorSessionState.AwaitingSmsCode,
            requiredMethods = [TwoFactorAuthMethod.SMS_KEY],
            completedMethods = [],
            currentExpectedMethod = TwoFactorAuthMethod.SMS_KEY
        };
    }

    private static string TwoFactorSessionGoldenJson()
    {
        return """
            {
              "accountId": "22222222-2222-2222-2222-222222222222",
              "webKey": "web-key",
              "preAuthRefreshToken": "CQgHBg==",
              "methods": [
                "EMAIL",
                "SMS_KEY"
              ],
              "userAuthIds": [
                "authenticator-app-user"
              ],
              "phoneNumbers": [
                "4045550100"
              ],
              "phoneCountryCode": [
                "1"
              ],
              "emailAddresses": [
                "reader@example.com"
              ],
              "chosenDestination": 1,
              "intraCodeKey": "intra-key",
              "challengedMethod": "SMS_KEY",
              "challengeCodeHash": "challenge-hash",
              "challengeExpiration": "2026-05-16T12:03:00Z",
              "challengeProviderTransactionId": "provider-transaction",
              "challengeAttempts": 1,
              "challengeResends": 2,
              "nextChallengeAllowedAt": "2026-05-16T12:01:00Z",
              "authenticatorAppUsage": 3,
              "smsKeyUsage": 4,
              "smsUsage": 5,
              "createdOn": "2026-05-16T12:00:00Z",
              "expiration": "2026-05-16T12:05:00Z",
              "cutOff": "2026-05-18T00:00:00Z",
              "features": "rawrzilla",
              "accountSecurityStamp": "55555555-5555-5555-5555-555555555555",
              "priorActiveAccessTokenHash": null,
              "availableConfigurationsSnapshot": [
                "SMS",
                "EMAIL"
              ],
              "selectedConfiguration": "SMS",
              "state": "AwaitingSmsCode",
              "requiredMethods": [
                "SMS_KEY"
              ],
              "completedMethods": [],
              "currentExpectedMethod": "SMS_KEY",
              "progressVersion": 1,
              "challengeId": null
            }
            """;
    }

    private static UserCacheSettings ActiveUserSettings(int database)
    {
        return new UserCacheSettings
        {
            servers = "localhost",
            port = 6379,
            database = database,
            clientName = "treehammock-tests-active",
            password = string.Empty
        };
    }

    private static TwoFactorSessionCacheSettings TwoFactorSettings(int database)
    {
        return new TwoFactorSessionCacheSettings
        {
            servers = "localhost",
            port = 6379,
            database = database,
            clientName = "treehammock-tests-2fa",
            password = string.Empty
        };
    }
}
