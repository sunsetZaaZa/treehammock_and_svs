using System.Text;

using AutoFixture;
using AutoFixture.AutoNSubstitute;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.DependencyInjection;
using Newtonsoft.Json;
using NSubstitute;
using NodaTime;
using Shouldly;

using treehammock.Controllers;
using treehammock.Models.Api;
using treehammock.DataLayer.Account;
using treehammock.DataLayer.Cache;
using treehammock.Models.Authentication;
using treehammock.Repos;
using treehammock.Rigging.Authorization;
using treehammock.Rigging.Cache;
using treehammock.Rigging.Config;
using treehammock.Rigging.Security;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Replay;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;
using treehammock.Services;

namespace treehammock.Tests.Infrastructure;

public sealed class AccountControllerHarness
{
    public CapturingDurableDelivery Delivery { get; } = new();
    public const string ValidPassword = "CorrectHorseBatteryStaple1!";

    public AccountControllerHarness()
    {
        Fixture = new Fixture();
        Fixture.Customize(new AutoNSubstituteCustomization { ConfigureMembers = true });

        AccountRepo = Fixture.Freeze<IAccountRepo>();
        SessionRepo = Fixture.Freeze<ISessionRepo>();
        ActiveUserCacheService = Fixture.Freeze<IActiveUserCacheService>();
        TwoFactorSessionService = Fixture.Freeze<ITwoFactorSessionService>();
        JwtUtility = Fixture.Freeze<IJsonWebTokenUtility>();
        TwoFactorService = Fixture.Freeze<ITwoFactorAuthenticateService>();
        AccountService = Fixture.Freeze<IAccountService>();
        AbuseCounterStore = Fixture.Freeze<IAbuseCounterStore>();
        LoginAbuseCounterKeyFactory = new LoginAbuseCounterKeyFactory();
        AuthenticatedMutationIdempotencyService = Fixture.Freeze<IAuthenticatedMutationIdempotencyService>();
        SensitiveActionService = Fixture.Freeze<IAccountSensitiveActionService>();
        SensitiveActionService.ValidateAsync(Arg.Any<SensitiveActionValidationCommand>(), Arg.Any<CancellationToken>())
            .Returns(call => Task.FromResult(new SensitiveActionValidationResult(
                true,
                HttpMessage.SENSITIVE_ACTION_TOKEN_VALIDATED,
                AccountSensitiveActionService.TokenValidatedCode,
                call.ArgAt<SensitiveActionValidationCommand>(0).Purpose,
                Grant: new(call.ArgAt<SensitiveActionValidationCommand>(0).SessionBindingHash, "test-token-hash", "test-target-hash",
                    call.ArgAt<SensitiveActionValidationCommand>(0).Target ?? SensitiveActionTargets.DefaultSetup))));
        AuthenticatedMutationIdempotencyService.BeginAsync(Arg.Any<AuthenticatedMutationIdempotencyRequest>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(AuthenticatedMutationIdempotencyBeginResult.NotAppliedResult()));
        AuthenticatedMutationIdempotencyService.CompleteAsync(Arg.Any<AuthenticatedMutationIdempotencyReservation?>(), Arg.Any<int>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(Task.CompletedTask);

        RegistrationSettings = new RegistrationSettings
        {
            MinUsernameLength = 3,
            MaxUsernameLength = 30,
            MinPasswordLength = 8,
            MaxPasswordLength = 128,
            MaxEmailAddressLength = 255,
            AccountMetaDataRetries = 3,
            VerifyAccountPeriodWeeks = 0,
            VerifyAccountPeriodDays = 1,
            VerifyAccountPeriodHours = 0,
            EmailChangeVerifyPeriodWeeks = 0,
            EmailChangeVerifyPeriodDays = 1,
            EmailChangeVerifyPeriodHours = 0,
            AccountDeleteTokenPeriodWeeks = 0,
            AccountDeleteTokenPeriodDays = 1,
            AccountDeleteTokenPeriodHours = 0,
            PublicOrigin = "http://localhost.test",
            DeleteRequestCooldownMinutes = 15,
            DeleteRequestWindowHours = 24,
            DeleteMaxRequestsPerWindow = 8,
            DeleteMaxFinalizeFailures = 5,
            DeleteFinalizeLockoutMinutes = 30
        };

        JwtSettings = new JWTSettings
        {
            JsonWebTokenIssuer = "treehammock-tests",
            RefreshTokenAliveDays = 0,
            RefreshTokenAliveHours = 1,
            RefreshTokenAliveMinutes = 0,
            RefreshTokenAliveDays_2FA = 0,
            RefreshTokenAliveHours_2FA = 0,
            RefreshTokenAliveMinutes_2FA = 2,
            RefreshTokenAliveDays_DB = 7,
            RefreshTokenAliveHours_DB = 0,
            RefreshTokenAliveMinutes_DB = 0,
            RefreshTokenAliveDays_Short = 0,
            RefreshTokenAliveHours_Short = 0,
            RefreshTokenAliveMinutes_Short = 15,
            RefreshTokenBytes = 64,
        };

        LoginSettings = new LoginSettings
        {
            PasswordRetryLimit = 3,
            TwoAuthRetryLimit = 3,
            TwoFactorChallengeResendCooldownSeconds = 30,
            TwoFactorChallengePepper = "test-two-factor-pepper",
            Argon2Iterations = 3,
            Argon2MemoryBytes = 67108864
        };

        // Direct-action substitution only; real SQL transitions have dedicated COR08 schedules.
        AccountRepo.ClearLoginAttempts(Arg.Any<Guid>(), Arg.Any<Guid>(), Arg.Any<Guid>(), Arg.Any<short>(), Arg.Any<Instant?>(), Arg.Any<bool>(), Arg.Any<CancellationToken>())
            .Returns(new treehammock.DataLayer.Security.LoginAttemptTransition(true, "CLEARED", 0, null, Guid.NewGuid()));
        AbuseControlSettings = new AbuseControlSettings();
        AbuseCounterStore.IncrementAsync(Arg.Any<AbuseCounterKey>(), Arg.Any<AbuseCounterLimit>(), Arg.Any<CancellationToken>())
            .Returns(call =>
            {
                var limit = call.ArgAt<AbuseCounterLimit>(1);
                return Task.FromResult(new CounterDecision(
                    Allowed: true,
                    CurrentCount: 1,
                    Limit: limit.MaxAttempts,
                    Window: limit.Window,
                    RetryAfter: null,
                    ReasonCode: null));
            });
        AbuseCounterStore.ResetAsync(Arg.Any<AbuseCounterKey>(), Arg.Any<CancellationToken>())
            .Returns(Task.CompletedTask);
    }

    public LoginProofTestDouble ProofState { get; } = new();
    public ILoginProofRepo LoginProofs => ProofState.Repo;
    public IFixture Fixture { get; }
    public IAccountRepo AccountRepo { get; }
    public ISessionRepo SessionRepo { get; }
    public IActiveUserCacheService ActiveUserCacheService { get; }
    public ITwoFactorSessionService TwoFactorSessionService { get; }
    public IJsonWebTokenUtility JwtUtility { get; }
    public ITwoFactorAuthenticateService TwoFactorService { get; }
    public IAccountService AccountService { get; }
    public IAbuseCounterStore AbuseCounterStore { get; }
    public ILoginAbuseCounterKeyFactory LoginAbuseCounterKeyFactory { get; }
    public IAuthenticatedMutationIdempotencyService AuthenticatedMutationIdempotencyService { get; }
    public IAccountSensitiveActionService SensitiveActionService { get; }
    public RegistrationSettings RegistrationSettings { get; }
    public JWTSettings JwtSettings { get; }
    public LoginSettings LoginSettings { get; }
    public AbuseControlSettings AbuseControlSettings { get; }
    public EmailTemplateSettings EmailTemplateSettings { get; } = new();
    public DefaultHttpContext HttpContext { get; private set; } = new();

    public AccountRegistrationController CreateRegistrationController() => CreateBoundedController<AccountRegistrationController>();

    public AccountLoginController CreateLoginController() => CreateBoundedController<AccountLoginController>();

    public AccountTwoFactorController CreateTwoFactorController() => CreateBoundedController<AccountTwoFactorController>();

    public AccountProfileController CreateProfileController() => CreateBoundedController<AccountProfileController>();

    public AccountDeleteController CreateDeleteController() => CreateBoundedController<AccountDeleteController>();

    public AccountSessionController CreateSessionController() => CreateBoundedController<AccountSessionController>();

    private TController CreateBoundedController<TController>()
        where TController : AccountControllerBase
    {
        HttpContext = new DefaultHttpContext();
        HttpContext.RequestServices = new ServiceCollection()
            .AddSingleton<treehammock.Rigging.Delivery.IDurableDeliveryService>(Delivery)
            .AddSingleton<IOptions<EmailSubjectSettings>>(Options.Create(new EmailSubjectSettings()))
            .AddSingleton(SensitiveActionService)
            .AddSingleton(LoginProofs)
            .BuildServiceProvider();

        var controller = (TController)Activator.CreateInstance(
            typeof(TController),
            AccountRepo,
            SessionRepo,
            ActiveUserCacheService,
            TwoFactorSessionService,
            JwtUtility,
            TwoFactorService,
            AccountService,
            AbuseCounterStore,
            LoginAbuseCounterKeyFactory,
            Options.Create(RegistrationSettings),
            Options.Create(JwtSettings),
            Options.Create(LoginSettings),
            Options.Create(AbuseControlSettings),
            Options.Create(EmailTemplateSettings),
            null,
            AuthenticatedMutationIdempotencyService)!;

        controller.ControllerContext = new ControllerContext
        {
            HttpContext = HttpContext
        };

        return controller;
    }


    public ActiveSession SetAuthenticatedSession(
        Guid? accountId = null,
        Guid? accountSecurityStamp = null,
        string hashedAccessToken = "unit-test-active-access-token-hash")
    {
        Instant createdOn = SystemClock.Instance.GetCurrentInstant();
        var session = treehammock.Tests.Support.EntitlementTestData.Attach(new ActiveSession(
            accountId ?? Fixture.Create<Guid>(),
            Fixture.CreateMany<byte>(JwtSettings.RefreshTokenBytes).ToArray(),
            0,
            createdOn,
            Period.FromMinutes(15),
            createdOn.Plus(Duration.FromMinutes(15)),
            createdOn.Plus(Duration.FromMinutes(30)),
            cutOff: null,
            features: FeatureSet.basic,
            accountSecurityStamp: accountSecurityStamp ?? Fixture.Create<Guid>()));

        HttpContext.Items[AuthContextItems.HashedAccessToken] = hashedAccessToken;
        HttpContext.Items[AuthContextItems.ActiveSession] = session;
        return session;
    }

    public AuthenticateLogin LoginPayload(
        string? emailAddress = "reader@example.com",
        string? username = null,
        string password = ValidPassword)
    {
        return username is null
            ? new AuthenticateLogin(emailAddress!, password)
            : new AuthenticateLogin(emailAddress!, username, password);
    }

    public IntraAccount Account(
        Guid? accountId = null,
        string password = ValidPassword,
        VerificationStatus verificationStatus = VerificationStatus.SUCCESSFUL,
        Instant? unlockWhen = null,
        byte[]? refreshToken = null,
        short refreshes = 0,
        Period? lifespan = null,
        short loginFailures = 0,
        bool hasTwoFactorAuth = false,
        TwoFactorAuthMethod twoFactorAuthMethod = TwoFactorAuthMethod.NONE,
        short authenticatorAppUsage = 0,
        short smsKeyUsage = 0,
        short smsUsage = 0,
        Instant? cutOff = null,
        string? twoFactorAccessToken = null,
        string? activeAccessTokenHash = null,
        Guid? accountSecurityStamp = null)
    {
        return new IntraAccount(
            accountId ?? Fixture.Create<Guid>(),
            HashPassword(password),
            Fixture.Create<string>(),
            verificationStatus,
            RandomBytes(AccountCryptoSizes.SaltOneBytes),
            RandomBytes(AccountCryptoSizes.SivBytes),
            RandomBytes(AccountCryptoSizes.NonceBytes),
            unlockWhen,
            refreshToken,
            refreshes,
            3,
            lifespan ?? Period.FromHours(1),
            loginFailures,
            twoFactorAccessToken,
            authenticatorAppUsage,
            smsKeyUsage,
            smsUsage,
            hasTwoFactorAuth,
            Country.NONE,
            cutOff,
            null,
            FeatureSet.basic,
            activeAccessTokenHash,
            accountSecurityStamp: accountSecurityStamp ?? Fixture.Create<Guid>())
        {
            twoFactorAuthMethod = twoFactorAuthMethod
        };
    }

    public static AuthenticateResponse ExtractAuthenticate(ActionResult<ApiResponse<AuthenticateResponse>> result, int? expectedStatusCode = null)
    {
        return ExtractData(result, expectedStatusCode);
    }

    public static T ExtractData<T>(ActionResult<ApiResponse<T>> result, int? expectedStatusCode = null)
        where T : class
    {
        ApiResponse<T> envelope = ExtractEnvelope(result, expectedStatusCode);
        envelope.data.ShouldNotBeNull();
        return envelope.data!;
    }

    public static ApiResponse<T> ExtractEnvelope<T>(ActionResult<ApiResponse<T>> result, int? expectedStatusCode = null)
    {
        ObjectResult objectResult = result.Result.ShouldBeOfType<ObjectResult>();
        if (expectedStatusCode.HasValue)
        {
            objectResult.StatusCode.ShouldBe(expectedStatusCode.Value);
        }

        ApiResponse<T> envelope = objectResult.Value.ShouldBeOfType<ApiResponse<T>>();
        envelope.statusCode.ShouldBe(objectResult.StatusCode!.Value);
        return envelope;
    }

    public static T Deserialize<T>(string json)
        where T : class
    {
        var response = JsonConvert.DeserializeObject<T>(json);
        response.ShouldNotBeNull();
        return response;
    }

    private byte[] HashPassword(string password)
    {
        return Argon2idPasswordHashCodec.HashToStorageBytes(
            password,
            LoginSettings.Argon2Iterations,
            LoginSettings.Argon2MemoryBytes);
    }

    private byte[] RandomBytes(int length)
    {
        return Fixture.CreateMany<byte>(length).ToArray();
    }
}
