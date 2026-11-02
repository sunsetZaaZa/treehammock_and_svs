using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using NodaTime;
using NSubstitute;
using Shouldly;
using StackExchange.Redis;

using treehammock.DataLayer.Cache;
using treehammock.Models.Api;
using treehammock.Repos;
using treehammock.Rigging.Authorization;
using treehammock.Rigging.Cache;
using treehammock.Rigging.Replay;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;
using treehammock.Services;
using treehammock.Tests.Infrastructure;

namespace treehammock.Tests.Integration;

public class AccountAdjustIntegrationTests
{
    private const string AuthenticatedAccessToken = "integration-active-access-token";

    [Fact]
    public async Task Authenticated_adjust_empty_body_object_returns_validation_failed()
    {
        using var factory = AuthenticatedFactory();
        using var client = CreateAuthenticatedHttpsClient(factory);

        using var response = await PostJsonWithIdempotency(client, "/account/adjust", "{}", "adjust-empty-body-0001");

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        using JsonDocument document = await AccountFailureAssertions.ReadJson(response);
        AccountFailureAssertions.Failure(response, document, StatusCodes.Status400BadRequest, ApiResponses.ValidationFailedCode, dataField: "result", dataValue: HttpMessage.ACCOUNT_ADJUST_FAILED.ToString());
        AccountFailureAssertions.ValidationField(document, string.Empty);
    }

    [Fact]
    public async Task Authenticated_adjust_missing_required_idempotency_key_returns_precondition_required()
    {
        using var factory = AuthenticatedFactory();
        using var client = CreateAuthenticatedHttpsClient(factory);

        using var response = await client.PostAsync(
            "/account/adjust",
            JsonContent("""
            {
              "username": "reader"
            }
            """));

        response.StatusCode.ShouldBe(HttpStatusCode.PreconditionRequired);
        using JsonDocument document = await AccountFailureAssertions.ReadJson(response);
        AccountFailureAssertions.Failure(response, document, StatusCodes.Status428PreconditionRequired, AuthenticatedMutationIdempotencyConstants.MissingRequiredKeyCode, dataField: "result", dataValue: HttpMessage.ACCOUNT_ADJUST_FAILED.ToString());
    }

    [Fact]
    public async Task Authenticated_adjust_email_only_returns_pending_verification()
    {
        using var factory = AuthenticatedFactory(configureAccountService: service =>
        {
            service.RequestEmailChange(Arg.Any<Guid>(), Arg.Any<Guid>(), "reader@example.com",cancellationToken:Arg.Any<CancellationToken>(),grant:Arg.Any<treehammock.DataLayer.Security.SensitiveActionGrant>())
                .Returns(Task.FromResult<AccountAdjustResult?>(new AccountAdjustResult(true, "ACCOUNT_ADJUST_EMAIL_VERIFICATION_PENDING", null, "reader@example.com")));
        });
        using var client = CreateAuthenticatedHttpsClient(factory);
        client.DefaultRequestHeaders.Add("Sensitive-Action-Token","fresh-proof");

        using var response = await PostJsonWithIdempotency(
            client,
            "/account/adjust",
            """
            {
              "emailAddress": "reader@example.com"
            }
            """,
            "adjust-email-only-0001");

        response.StatusCode.ShouldBe(HttpStatusCode.Accepted);
        using JsonDocument document = await AccountFailureAssertions.ReadJson(response);
        AssertSuccessEnvelope(document, StatusCodes.Status202Accepted, "ACCOUNT_ADJUST_EMAIL_VERIFICATION_PENDING");
        document.RootElement.GetProperty("data").GetProperty("result").GetString().ShouldBe(HttpMessage.ACCOUNT_ADJUST_EMAIL_VERIFICATION_PENDING.ToString());
    }

    [Fact]
    public async Task Authenticated_adjust_username_only_returns_success()
    {
        using var factory = AuthenticatedFactory(repo =>
        {
            repo.ModifyUsername(Arg.Any<Guid>(), Arg.Any<Guid>(), "reader", cancellationToken: Arg.Any<CancellationToken>())
                .Returns(Task.FromResult<AccountAdjustResult?>(new AccountAdjustResult(true, "ACCOUNT_ADJUST_SUCCEEDED")));
        });
        using var client = CreateAuthenticatedHttpsClient(factory);

        using var response = await PostJsonWithIdempotency(
            client,
            "/account/adjust",
            """
            {
              "username": "reader"
            }
            """,
            "adjust-username-only-0001");

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        using JsonDocument document = await AccountFailureAssertions.ReadJson(response);
        AssertSuccessEnvelope(document, StatusCodes.Status200OK, "ACCOUNT_ADJUST_SUCCEEDED");
        document.RootElement.GetProperty("data").GetProperty("result").GetString().ShouldBe(HttpMessage.ACCOUNT_ADJUST_SUCCEEDED.ToString());
    }

    [Fact]
    public async Task Authenticated_adjust_duplicate_username_returns_bad_request()
    {
        using var factory = AuthenticatedFactory(repo =>
        {
            repo.ModifyUsername(Arg.Any<Guid>(), Arg.Any<Guid>(), "reader", cancellationToken: Arg.Any<CancellationToken>())
                .Returns(Task.FromResult<AccountAdjustResult?>(new AccountAdjustResult(false, "ACCOUNT_ADJUST_DUPLICATE_USERNAME")));
        });
        using var client = CreateAuthenticatedHttpsClient(factory);

        using var response = await PostJsonWithIdempotency(
            client,
            "/account/adjust",
            """
            {
              "username": "reader"
            }
            """,
            "adjust-duplicate-username-0001");

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        using JsonDocument document = await AccountFailureAssertions.ReadJson(response);
        AccountFailureAssertions.Failure(response, document, StatusCodes.Status400BadRequest, "ACCOUNT_ADJUST_DUPLICATE_USERNAME", dataField: "result", dataValue: HttpMessage.ACCOUNT_ADJUST_DUPLICATE_USERNAME.ToString());
        document.RootElement.GetProperty("data").GetProperty("result").GetString().ShouldBe(HttpMessage.ACCOUNT_ADJUST_DUPLICATE_USERNAME.ToString());
    }

    [Theory]
    [InlineData("""
        {
          "emailAddress": "",
          "username": "reader"
        }
        """, "emailAddress", false)]
    [InlineData("""
        {
          "emailAddress": "reader@example.com",
          "username": ""
        }
        """, "username", true)]
    public async Task Authenticated_adjust_blank_or_email_plus_valid_field_returns_validation_failed(string json, string expectedField, bool domainValidation)
    {
        using var factory = AuthenticatedFactory();
        using var client = CreateAuthenticatedHttpsClient(factory);

        using var response = await PostJsonWithIdempotency(client, "/account/adjust", json, $"adjust-validation-{Guid.NewGuid():N}");

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        using JsonDocument document = await AccountFailureAssertions.ReadJson(response);
        // Empty email fails the model's EmailAddress attribute; the other case reaches domain validation.
        if (domainValidation)
        {
            AccountFailureAssertions.Failure(response, document, StatusCodes.Status400BadRequest, ApiResponses.ValidationFailedCode,
                dataField: "result", dataValue: HttpMessage.ACCOUNT_ADJUST_FAILED.ToString());
            AccountFailureAssertions.ValidationField(document, string.Empty);
        }
        else
        {
            AccountFailureAssertions.Failure(response, document, StatusCodes.Status400BadRequest, ApiResponses.ValidationFailedCode);
        }
        AccountFailureAssertions.ValidationField(document, expectedField);
    }

    [Fact]
    public async Task Authenticated_adjust_with_stale_cached_session_trust_returns_unauthorized()
    {
        using var factory = AuthenticatedFactory(trustStatus: CachedSessionTrustStatus.AccountSecurityStampMismatch);
        using var client = CreateAuthenticatedHttpsClient(factory);

        using var response = await PostJsonWithIdempotency(
            client,
            "/account/adjust",
            """
            {
              "username": "reader"
            }
            """,
            "adjust-stale-session-0001");

        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        response.Headers.TryGetValues("AppStatus", out IEnumerable<string>? appStatuses).ShouldBeTrue();
        appStatuses.ShouldContain(AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString());

        using JsonDocument document = await AccountFailureAssertions.ReadJson(response);
        AccountFailureAssertions.Failure(response, document, StatusCodes.Status401Unauthorized, HttpMessage.AUTHENTICATION_FAILED.ToString(), dataField: "result", dataValue: HttpMessage.AUTHENTICATION_FAILED.ToString());
    }

    private static TreehammockWebApplicationFactory AuthenticatedFactory(
        Action<IAccountRepo>? configureAccountRepo = null,
        CachedSessionTrustStatus trustStatus = CachedSessionTrustStatus.Valid,
        Action<IAccountService>? configureAccountService = null)
    {
        return new TreehammockWebApplicationFactory(TestConfiguration.ValidSettings(), services =>
        {
            Instant createdOn = SystemClock.Instance.GetCurrentInstant();
            Instant sessionExpiration = createdOn.Plus(Duration.FromMinutes(15));
            var session = treehammock.Tests.Support.EntitlementTestData.Attach(new ActiveSession(
                Guid.NewGuid(),
                RandomNumberGenerator.GetBytes(64),
                0,
                createdOn,
                Period.FromMinutes(15),
                createdOn.Plus(Duration.FromMinutes(15)),
                sessionExpiration,
                cutOff: null,
                features: FeatureSet.basic,
                accountSecurityStamp: Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-000000000001")));

            var activeUsers = Substitute.For<IActiveUserCacheService>();
            activeUsers.GetSession(Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<ActiveSession?>(session));
            activeUsers.SetSession(
                    Arg.Any<string>(),
                    Arg.Any<ActiveSession>(),
                    Arg.Any<TimeSpan>(),
                    Arg.Any<CommandFlags>(), cancellationToken: Arg.Any<CancellationToken>())
                .Returns(Task.FromResult(true));
            activeUsers.RevokeSession(Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(true));

            var jwtUtility = Substitute.For<IJsonWebTokenUtility>();
            jwtUtility.ValidateAccessToken(
                    Arg.Any<string>(),
                    Arg.Any<byte[]>(),
                    Arg.Any<Instant>(),
                    Arg.Any<Instant>(),
                    Arg.Any<string>(),
                    Arg.Any<Duration?>())
                .Returns(Task.FromResult((IntraMessage.TOKEN_PASSED_VALIDATION, (string?)"integration-web-key")));

            var sessionRepo = Substitute.For<ISessionRepo>();
            sessionRepo.ValidateCachedSessionTrust(
                    Arg.Any<string>(),
                    session.accountId,
                    session.securityStamp,
                    session.accountSecurityStamp, cancellationToken: Arg.Any<CancellationToken>())
                .Returns(Task.FromResult<CachedSessionTrustResult?>(BuildTrustResult(session, trustStatus)));

            var accountRepo = Substitute.For<IAccountRepo>();
            configureAccountRepo?.Invoke(accountRepo);
            var accountService = Substitute.For<IAccountService>();
            var sensitive=Substitute.For<IAccountSensitiveActionService>();
            sensitive.ValidateAsync(Arg.Any<SensitiveActionValidationCommand>(),Arg.Any<CancellationToken>()).Returns(call=>new SensitiveActionValidationResult(true,HttpMessage.SENSITIVE_ACTION_TOKEN_VALIDATED,"SENSITIVE_ACTION_TOKEN_VALIDATED",Grant:new(call.ArgAt<SensitiveActionValidationCommand>(0).SessionBindingHash,"fixture-grant","fixture-target",call.ArgAt<SensitiveActionValidationCommand>(0).Target!)));
            services.RemoveAll<IAccountSensitiveActionService>();services.AddSingleton(sensitive);
            configureAccountService?.Invoke(accountService);

            services.RemoveAll<IActiveUserCacheService>();
            services.RemoveAll<IJsonWebTokenUtility>();
            services.RemoveAll<ISessionRepo>();
            services.RemoveAll<IAccountRepo>();
            services.RemoveAll<IAccountService>();
            services.RemoveAll<IAuthenticatedMutationIdempotencyService>();

            services.AddSingleton(activeUsers);
            services.AddSingleton(jwtUtility);
            services.AddSingleton(sessionRepo);
            services.AddSingleton(accountRepo);
            services.AddSingleton(accountService);
            services.AddSingleton<IAuthenticatedMutationIdempotencyService>(new AllowingAuthenticatedMutationIdempotencyService());
        });
    }

    private static CachedSessionTrustResult BuildTrustResult(ActiveSession session, CachedSessionTrustStatus trustStatus)
    {
        return trustStatus == CachedSessionTrustStatus.Valid
            ? new CachedSessionTrustResult(
                CachedSessionTrustStatus.Valid,
                AccessExpiration: session.accessExpiration,
                SessionExpiration: session.sessionExpiration,
                CutOff: session.cutOff,
                SecurityStamp: session.securityStamp,
                AccountSecurityStamp: session.accountSecurityStamp, Entitlements: treehammock.Tests.Support.EntitlementTestData.ForAccount(session.accountId))
            : new CachedSessionTrustResult(trustStatus, Code: trustStatus.ToString());
    }

    private static HttpClient CreateAuthenticatedHttpsClient(TreehammockWebApplicationFactory factory)
    {
        HttpClient client = factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false
        });

        client.DefaultRequestHeaders.Add("AccessToken", AuthenticatedAccessToken);
        return client;
    }

    private static async Task<HttpResponseMessage> PostJsonWithIdempotency(
        HttpClient client,
        string route,
        string json,
        string key)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, route)
        {
            Content = JsonContent(json)
        };

        request.Headers.Add(AuthenticatedMutationIdempotencyConstants.HeaderName, key);
        return await client.SendAsync(request);
    }

    private static StringContent JsonContent(string json)
    {
        return new StringContent(json, Encoding.UTF8, "application/json");
    }

    private static void AssertSuccessEnvelope(JsonDocument document, int statusCode, string code)
    {
        JsonElement root = document.RootElement;
        root.GetProperty("success").GetBoolean().ShouldBeTrue();
        root.GetProperty("statusCode").GetInt32().ShouldBe(statusCode);
        root.GetProperty("code").GetString().ShouldBe(code);
    }

}
