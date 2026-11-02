using Treehammock.SessionValidation.Core;
using treehammock.Rigging.Delivery;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

using treehammock.Repos;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Authorization;
using treehammock.Rigging.Cache;
using treehammock.Rigging.Config;
using treehammock.Rigging.Database;
using treehammock.Rigging.Provider;
using treehammock.Rigging.Sidewalk;
using treehammock.Services;
using treehammock.Services.SystemTesting;
using treehammock.Rigging.Security;
using treehammock.Rigging.Replay;
using treehammock.Rigging.Health;
using treehammock.Rigging.Hosting;

namespace treehammock.Rigging.DependencyInjection;

public static class TreehammockServiceCollectionExtensions
{
    public static IServiceCollection AddTreehammockServices(this IServiceCollection services, IConfiguration configuration, IHostEnvironment? environment = null)
    {
        // Reject invalid activation before registering any provider or discovering privileged routes.
        var systemTestCapability = SystemTestCapability.FromConfiguration(configuration, environment);
        services.AddSingleton(systemTestCapability);
        services.AddSingleton(HostSystemTestIdentity.FromConfiguration(configuration, systemTestCapability));
        services.AddControllers().ConfigureApplicationPartManager(manager =>
            manager.FeatureProviders.Add(new SystemTestControllerFeatureProvider(systemTestCapability)));
        services.AddHttpContextAccessor();
        services.AddHttpClient();
        services.AddHttpClient("treehammock-twilio", client => { client.Timeout = Timeout.InfiniteTimeSpan; client.MaxResponseContentBufferSize = 16384; })
            .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false });

        services.AddValidatedOptions<SecurityOperationSettings>(configuration, "SecurityOperationSettings");
        services.AddValidatedOptions<RetentionSettings>(configuration, "RetentionSettings");
        if (environment?.IsProduction() == true)
            services.AddOptions<SecurityOperationSettings>().Validate(settings =>
                settings.HmacKeys is not null && !settings.HmacKeys.Values.Contains("dHJlZWhhbW1vY2stY29yMDQtdGVzdC1rZXktMDAwMDE=", StringComparer.Ordinal),
                "Production security operations require independent shared keys, never example keys.").ValidateOnStart();
        services.AddValidatedOptions<DatabaseSettings>(configuration, "DatabaseSettings");
        if (environment?.IsProduction() == true)
            services.AddOptions<DatabaseSettings>().Validate(settings =>
                string.Equals(settings.profile, "Production", StringComparison.OrdinalIgnoreCase),
                "Production hosting requires DatabaseSettings.profile=Production (VerifyFull TLS).").ValidateOnStart();
        services.AddValidatedOptions<UserCacheSettings>(configuration, "ActiveUserBundleSettings");
        services.AddValidatedOptions<TwoFactorSessionCacheSettings>(configuration, "TwoFactorSessionBundleSettings");
        services.AddValidatedOptions<AbuseCounterCacheSettings>(configuration, "AbuseCounterBundleSettings");
        services.AddValidatedOptions<SessionCacheFallbackSettings>(configuration, "SessionCacheFallbackSettings");
        services.AddValidatedOptions<SessionCacheWarmupSettings>(configuration, "SessionCacheWarmupSettings");
        services.AddValidatedOptions<AbuseControlSettings>(configuration, "AbuseControlSettings");
        services.AddValidatedOptions<JWTSettings>(configuration, "JWTSettings");
        services.AddValidatedOptions<LoginSettings>(configuration, "LoginSettings");
        services.AddValidatedOptions<RegistrationSettings>(configuration, "RegistrationSettings");
        services.AddOptions<RegistrationSettings>().Validate(settings =>
            VerificationLinkBuilder.AllowedForEnvironment(settings.PublicOrigin, environment?.EnvironmentName),
            "RegistrationSettings PublicOrigin requires explicit non-loopback HTTPS in Production; HTTP is allowed only in named local/test/container lanes.").ValidateOnStart();
        services.AddSingleton(provider => new VerificationLinkBuilder(provider.GetRequiredService<IOptions<RegistrationSettings>>().Value.PublicOrigin));
        services.AddValidatedOptions<PasswordResetSettings>(configuration, "PasswordResetSettings");
        services.AddValidatedOptions<SensitiveActionSettings>(configuration, "SensitiveActionSettings");
        services.AddValidatedOptions<TotpSettings>(configuration, "TotpSettings");
        services.AddValidatedOptions<SMTPSettings>(configuration, "SMTPSettings");
        services.AddOptions<SMTPSettings>().Validate(settings =>
            SmtpTransportPolicy.AllowedForEnvironment(settings, environment?.EnvironmentName),
            "SMTPSettings plaintext is restricted to explicitly permitted literal loopback relays in Testing; other hosts require authenticated TLS.").ValidateOnStart();
        services.AddSingleton(provider => new SmtpTransportPolicy(provider.GetRequiredService<IOptions<SMTPSettings>>().Value, environment?.EnvironmentName));
        services.AddSingleton<ISmtpClientFactory, SmtpClientFactory>();
        services.AddValidatedOptions<HealthProbeSettings>(configuration, "HealthProbeSettings");
        services.AddValidatedOptions<ProviderHealthSettings>(configuration, "ProviderHealthSettings");
        services.AddValidatedOptions<DeliveryOutboxSettings>(configuration, "DeliveryOutboxSettings");
        services.AddValidatedOptions<EmailTemplateSettings>(configuration, "EmailTemplateSettings");
        services.AddValidatedOptions<EmailSubjectSettings>(configuration, "EmailSubjectSettings");
        services.AddSingleton<IValidateOptions<SidewalkSettings>, SelectedSmsTransportValidator>();
        services.AddValidatedOptions<SidewalkSettings>(configuration, "SidewalkSettings");
        services.AddValidatedOptions<HostingSettings>(configuration, "HostingSettings");
        services.AddOptions<RequestBodySettings>()
            .Bind(configuration.GetSection("RequestBodySettings"), binder => binder.ErrorOnUnknownConfiguration = true)
            .Validate(settings => ConfigurationValidation.TryValidate(settings, out _), "RequestBodySettings contains invalid request budgets.")
            .ValidateOnStart();
        services.AddSingleton<RequestBodyPolicy>();

        // 1.0.0 uses StorageContext as the PostgreSQL contract owner for account, session, and password-reset rows.
        // A dedicated SessionContext or split database topology is future cache/storage design work.
        services.AddSingleton(provider =>
        {
            var settings = provider.GetRequiredService<IOptions<DatabaseSettings>>();
            if (provider.GetService<IHostEnvironment>()?.IsProduction() == true &&
                !string.Equals(settings.Value.profile, "Production", StringComparison.OrdinalIgnoreCase))
                throw new OptionsValidationException("DatabaseSettings", typeof(DatabaseSettings),
                    ["Production hosting requires DatabaseSettings.profile=Production (VerifyFull TLS)."]);
            return new StorageContext(settings, provider.GetRequiredService<IOptions<SecurityOperationSettings>>(),
                provider.GetService<IHostApplicationLifetime>()?.ApplicationStopping ?? CancellationToken.None);
        });
        services.AddSingleton(provider => provider.GetRequiredService<StorageContext>().SecurityOperations);
        services.AddSingleton<treehammock.Rigging.Delivery.DeliveryPayloadProtector>();
        services.AddSingleton<DeliveryExecutionPolicy>();
        services.AddHostedService(provider => provider.GetRequiredService<DeliveryExecutionPolicy>());
        services.AddSingleton<DeliveryOutboxRepo>();
        services.AddSingleton<treehammock.Rigging.Delivery.IDurableDeliveryService,DurableDeliveryService>();
        services.AddSingleton<treehammock.Rigging.Delivery.IDeliveryProvider,DeliveryProviderAdapter>();
        services.AddHostedService<DeliveryOutboxWorker>();
        services.AddSingleton<RetentionRepo>();
        services.AddHostedService<RetentionWorker>();
        services.AddSingleton<EntitlementRepo>();
        services.AddHostedService<EntitlementRenewalWorker>();
        services.AddSingleton<CacheConnectionOwner>();
        services.AddHostedService(provider => provider.GetRequiredService<CacheConnectionOwner>());

        // Repos | Connection pooling is in use. Singleton is the only option because of pooling.
        services.AddSingleton<IAccountRecoveryRepo, AccountRecoveryRepo>();
        services.AddSingleton<IAccountRepo, AccountRepo>();
        services.AddSingleton<IActivationRepo, ActivationRepo>();
        services.AddSingleton<ISessionRepo, SessionRepo>();
        services.AddSingleton<ISessionCacheWarmupRepo, SessionCacheWarmupRepo>();
        services.AddHostedService<SessionCacheWarmupWorker>();
        services.AddSingleton<ISessionRefreshRepo, SessionRefreshRepo>();
        services.AddSingleton<ILoginProofRepo, LoginProofRepo>();
        services.AddSingleton<SessionRefreshService>();
        services.AddSingleton<IPasswordResetRepo, PasswordResetRepo>();
        services.AddSingleton<IPasswordResetTotpRepo, PasswordResetTotpRepo>();
        services.AddSingleton<ISensitiveActionTokenRepo, SensitiveActionTokenRepo>();
        services.AddSingleton<IAuthenticatorAppEnrollmentRepo, AuthenticatorAppEnrollmentRepo>();

        services.AddSingleton<ITwoFactorSessionService>(provider => new TwoFactorSessionService(
            provider.GetRequiredService<IOptions<TwoFactorSessionCacheSettings>>(),
            provider.GetRequiredService<CacheConnectionOwner>().Get(CacheProfile.TwoFactorSessions)));
        services.AddSingleton<IPasswordResetSessionService, PasswordResetSessionService>();
        services.AddSingleton<IActiveUserCacheService>(provider => new ActiveUserCacheService(
            provider.GetRequiredService<IOptions<UserCacheSettings>>(),
            provider.GetRequiredService<CacheConnectionOwner>().Get(CacheProfile.ActiveSessions)));
        services.AddSingleton<IPostgreSqlAbuseBudgetStore, PostgreSqlAbuseBudgetStore>();
        services.AddHostedService<PostgreSqlAbuseBudgetCleanupWorker>();
        services.AddSingleton<IAbuseCounterStore>(provider => new DragonflyAbuseCounterStore(
            provider.GetRequiredService<IOptions<AbuseCounterCacheSettings>>(),
            provider.GetRequiredService<IOptions<AbuseControlSettings>>(),
            provider.GetRequiredService<CacheConnectionOwner>().Get(CacheProfile.AbuseCounters),
            provider.GetRequiredService<IOptions<AbuseControlSettings>>().Value.CounterFailureMode == AbuseCounterFailureMode.RequirePostgreSqlBudgetV1
                ? provider.GetRequiredService<IPostgreSqlAbuseBudgetStore>() : null));
        services.AddSingleton<IDeliveryAbuseThrottleService, DeliveryAbuseThrottleService>();
        services.AddSingleton<IProviderHealthService>(provider => new ProviderHealthService(
            provider.GetRequiredService<IOptions<ProviderHealthSettings>>(), provider.GetRequiredService<IOptions<SMTPSettings>>(),
            provider.GetRequiredService<IOptions<SidewalkSettings>>(), provider.GetRequiredService<IOptions<AbuseControlSettings>>(),
            provider.GetRequiredService<CacheConnectionOwner>().Get(CacheProfile.AbuseCounters)));
        services.AddSingleton<ITreehammockTokenVerifier, TreehammockTokenVerifier>();
        services.AddSingleton<ITreehammockSessionPolicyEvaluator, TreehammockSessionPolicyEvaluator>();
        services.AddSingleton<IJsonWebTokenUtility, JsonWebTokenUtility>();
        services.AddSingleton<PasswordWorkLimiter>();
        services.AddSingleton<IPasswordWorkService, PasswordWorkService>();
        services.AddSingleton<ISignupAdmissionPolicy, SignupAdmissionPolicy>();
        services.AddSingleton<ISensitiveActionAdmissionPolicy, SensitiveActionAdmissionPolicy>();
        services.AddSingleton<IUserSecretHasher, Argon2idUserSecretHasher>();
        services.AddSingleton<IPasswordResetCodeGenerator, PasswordResetCodeGenerator>();
        services.AddSingleton<ILoginAbuseCounterKeyFactory, LoginAbuseCounterKeyFactory>();
        services.AddSingleton<IPasswordResetCodeHasher, PasswordResetCodeHasher>();
        services.AddSingleton<IPasswordResetRateLimitKeyFactory, PasswordResetRateLimitKeyFactory>();
        services.AddSingleton<IPasswordResetAbuseCounterKeyFactory, PasswordResetAbuseCounterKeyFactory>();
        services.AddSingleton<IAccountUnlockAbuseCounterKeyFactory, AccountUnlockAbuseCounterKeyFactory>();
        services.AddSingleton<IAccountTokenVerificationAbuseCounterKeyFactory, AccountTokenVerificationAbuseCounterKeyFactory>();
        services.AddSingleton<IActivationAbuseCounterKeyFactory, ActivationAbuseCounterKeyFactory>();
        services.AddSingleton<IAuthenticatedMutationIdempotencyService>(provider => new DragonflyAuthenticatedMutationIdempotencyService(
            provider.GetRequiredService<IOptions<AbuseCounterCacheSettings>>(),
            provider.GetRequiredService<IOptions<AbuseControlSettings>>(),
            provider.GetRequiredService<CacheConnectionOwner>().Get(CacheProfile.AbuseCounters),
            provider.GetRequiredService<StorageContext>()));
        services.AddSingleton<HealthDependencyService>();
        services.AddSingleton<IHealthDependencyService>(provider => provider.GetRequiredService<HealthDependencyService>());
        services.AddHostedService(provider => provider.GetRequiredService<HealthDependencyService>());
        services.AddHttpClient(TurnstileCaptchaVerifier.ClientName, client =>
        { client.Timeout = Timeout.InfiniteTimeSpan; client.MaxResponseContentBufferSize = 16384; })
            .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false });
        services.AddSingleton<ICaptchaVerifier, TurnstileCaptchaVerifier>();
        services.AddSingleton<ICaptchaContinuationStore, DragonflyCaptchaContinuationStore>();
        services.AddSingleton<IPasswordResetPublicGate>(provider => new PasswordResetPublicGate(
            provider.GetRequiredService<IAbuseCounterStore>(), provider.GetRequiredService<ICaptchaVerifier>(),
            provider.GetRequiredService<ICaptchaContinuationStore>(), provider.GetRequiredService<IOptions<PasswordResetSettings>>(),
            NodaTime.SystemClock.Instance));
        services.AddHostedService<PasswordResetCaptchaStartupGuard>();
        services.AddSingleton<IPasswordResetAbusePolicy, PasswordResetAbusePolicy>();
        services.AddSingleton<IPasswordResetDeliveryService, PasswordResetDeliveryService>();
        services.AddSingleton<IPasswordResetTotpVerifier, PasswordResetTotpVerifier>();
        services.AddSingleton<IPasswordResetPasswordMaterialFactory, PasswordResetPasswordMaterialFactory>();
        services.AddSingleton<ITotpSecretProtector, TotpSecretProtector>();
        services.AddSingleton<TotpReencryptionRepo>();
        services.AddSingleton<ITotpCodeVerifier, TotpCodeVerifier>();
        services.AddSingleton<IAuthenticatorAppSecretGenerator, AuthenticatorAppSecretGenerator>();
        services.AddSingleton<IAuthenticatorAppBase32Encoder, AuthenticatorAppBase32Encoder>();
        services.AddSingleton<IAuthenticatorAppProvisioningUriBuilder, AuthenticatorAppProvisioningUriBuilder>();
        services.AddSingleton<ITotpProvider, LocalTotpProvider>();
        services.AddSingleton<ITotpProviderRegistry, TotpProviderRegistry>();

        // Services | Anything that doesn't speak to a Cache or Database is a candidate for Transient.
        services.AddSingleton<IAccountRecoveryService, AccountRecoveryService>();
        services.AddSingleton<IAccountService, AccountService>();
        services.AddSingleton<ITwoFactorAuthenticateService, TwoFactorAuthenticateService>();
        services.AddSingleton<IActivationService, ActivationService>();
        services.AddSingleton<IPasswordResetService, PasswordResetService>();
        services.AddSingleton<IAccountSensitiveActionService, AccountSensitiveActionService>();
        services.AddSingleton<IAuthenticatorAppSetupService, AuthenticatorAppSetupService>();
        services.AddSingleton<IAuthenticatorAppLoginVerifier, AuthenticatorAppLoginVerifier>();
        services.AddSingleton<HTTPService>();
        if (systemTestCapability.CaptureEnabled)
        {
            services.AddSingleton<ISystemTestDeliveryCapture, SystemTestDeliveryCapture>();
            services.AddSingleton<ISMTPService, SystemTestSmtpService>();
            services.AddSingleton<ISmsSender, SystemTestSmsSender>();
        }
        else
        {
            services.AddSingleton<ISMTPService, SMTPService>();
            services.AddSingleton<ISmsSender, SmsSender>();
        }

        services.AddSingleton<IAwsSnsSmsClient, AwsSnsSmsClient>();
        services.AddSingleton<IAWSService, AWSService>();
        services.AddSingleton<ITwilioMessageClient, TwilioMessageClient>();
        services.AddSingleton<ITwilioSmsService, TwilioSmsService>();
        services.AddSingleton<AspenTrees>();

        return services;
    }

    private static OptionsBuilder<TOptions> AddValidatedOptions<TOptions>(
        this IServiceCollection services,
        IConfiguration configuration,
        string sectionName)
        where TOptions : class, new()
    {
        IConfigurationSection section = configuration.GetSection(sectionName);

        return services
            .AddOptions<TOptions>()
            .Bind(section, binder => binder.ErrorOnUnknownConfiguration = sectionName == "RegistrationSettings" || sectionName == "SMTPSettings" || sectionName == "HealthProbeSettings")
            .Validate(_ => section.Exists(), $"{sectionName} configuration section is required.")
            .Validate(options => ConfigurationValidation.TryValidate(options, out _), $"{sectionName} configuration is invalid or incomplete.")
            .ValidateOnStart();
    }
}
