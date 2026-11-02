using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Shouldly;

using treehammock.Rigging.Config;
using treehammock.Rigging.DependencyInjection;
using treehammock.Tests.Infrastructure;

namespace treehammock.Tests.Integration;

public class StartupConfigurationTests
{
    [Fact]
    public void App_starts_with_example_local_config()
    {
        using var factory = new TreehammockWebApplicationFactory();
        using var client = factory.CreateClient();

        client.ShouldNotBeNull();
    }

    [Theory]
    [InlineData("DatabaseSettings")]
    [InlineData("ActiveUserBundleSettings")]
    [InlineData("TwoFactorSessionBundleSettings")]
    [InlineData("AbuseCounterBundleSettings")]
    [InlineData("SessionCacheFallbackSettings")]
    [InlineData("AbuseControlSettings")]
    [InlineData("JWTSettings")]
    [InlineData("SMTPSettings")]
    [InlineData("PasswordResetSettings")]
    [InlineData("TotpSettings")]
    [InlineData("EmailSubjectSettings")]
    [InlineData("SidewalkSettings")]
    [InlineData("HostingSettings")]
    public void Missing_required_config_section_fails_startup(string missingSection)
    {
        using var factory = new TreehammockWebApplicationFactory(TestConfiguration.WithoutSection(missingSection));

        var exception = Record.Exception(() => factory.CreateClient());

        exception.ShouldNotBeNull();
        exception.ToString().ShouldContain(missingSection);
    }

    [Fact]
    public void Invalid_jwt_config_fails_options_validation()
    {
        var settings = TestConfiguration.ValidSettings();
        settings["JWTSettings:RefreshTokenBytes"] = "0";

        var services = new ServiceCollection();
        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(settings)
            .Build();

        services.AddTreehammockServices(configuration);

        using ServiceProvider provider = services.BuildServiceProvider();

        var exception = Record.Exception(() => provider.GetRequiredService<IOptions<JWTSettings>>().Value);

        exception.ShouldNotBeNull();
        exception.ShouldBeOfType<OptionsValidationException>();
        exception.Message.ShouldContain("JWTSettings");
    }

    [Fact]
    public void Valid_config_binds_required_options_without_default_runtime_values()
    {
        var services = new ServiceCollection();
        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(TestConfiguration.ValidSettings())
            .Build();

        services.AddTreehammockServices(configuration);

        using ServiceProvider provider = services.BuildServiceProvider();

        var database = provider.GetRequiredService<IOptions<DatabaseSettings>>().Value;
        var redis = provider.GetRequiredService<IOptions<UserCacheSettings>>().Value;
        var twoFactorRedis = provider.GetRequiredService<IOptions<TwoFactorSessionCacheSettings>>().Value;
        var abuseRedis = provider.GetRequiredService<IOptions<AbuseCounterCacheSettings>>().Value;
        var jwt = provider.GetRequiredService<IOptions<JWTSettings>>().Value;
        var abuse = provider.GetRequiredService<IOptions<AbuseControlSettings>>().Value;
        var emailTemplates = provider.GetRequiredService<IOptions<EmailTemplateSettings>>().Value;
        var emailSubjects = provider.GetRequiredService<IOptions<EmailSubjectSettings>>().Value;
        var registration = provider.GetRequiredService<IOptions<RegistrationSettings>>().Value;
        var passwordReset = provider.GetRequiredService<IOptions<PasswordResetSettings>>().Value;
        var totp = provider.GetRequiredService<IOptions<TotpSettings>>().Value;
        var smtp = provider.GetRequiredService<IOptions<SMTPSettings>>().Value;
        var sidewalk = provider.GetRequiredService<IOptions<SidewalkSettings>>().Value;
        var hosting = provider.GetRequiredService<IOptions<HostingSettings>>().Value;

        database.servers.ShouldNotBeNullOrWhiteSpace();
        database.database.ShouldNotBeNullOrWhiteSpace();
        database.userId.ShouldNotBeNullOrWhiteSpace();
        redis.servers.ShouldNotBeNullOrWhiteSpace();
        redis.port.ShouldBeGreaterThan(0);
        twoFactorRedis.servers.ShouldNotBeNullOrWhiteSpace();
        twoFactorRedis.port.ShouldBeGreaterThan(0);
        twoFactorRedis.database.ShouldNotBe(redis.database);
        abuseRedis.servers.ShouldNotBeNullOrWhiteSpace();
        abuseRedis.port.ShouldBeGreaterThan(0);
        abuseRedis.database.ShouldNotBe(redis.database);
        abuseRedis.database.ShouldNotBe(twoFactorRedis.database);
        jwt.JsonWebTokenIssuer.ShouldNotBeNullOrWhiteSpace();
        abuse.Enabled.ShouldBeTrue();
        abuse.CounterFailureMode.ShouldBe(AbuseCounterFailureMode.FailClosed);
        abuse.DragonflyTimeoutMilliseconds.ShouldBe(250);
        abuse.TwoFactor.Enabled.ShouldBeTrue();
        abuse.TwoFactor.MaxAttemptsPerChallenge.ShouldBe(5);
        abuse.TwoFactor.MaxSetupVerifyAttemptsPerAccount.ShouldBe(5);
        abuse.Delivery.Enabled.ShouldBeTrue();
        abuse.Delivery.MaxSmsDeliveriesPerAccountPerHour.ShouldBe(3);
        abuse.FailureCooldown.Enabled.ShouldBeTrue();
        abuse.FailureCooldown.FailureThreshold.ShouldBe(5);
        abuse.Login.Enabled.ShouldBeTrue();
        abuse.Login.MaxAttemptsPerIdentifierPerWindow.ShouldBe(10);
        abuse.Login.CaptchaChallengeEnabled.ShouldBeFalse();
        abuse.Login.CaptchaChallengeAfterAttempts.ShouldBe(5);
        abuse.PasswordReset.Enabled.ShouldBeTrue();
        abuse.PasswordReset.MaxRequestsPerIdentifierPerHour.ShouldBe(5);
        abuse.AccountUnlock.Enabled.ShouldBeTrue();
        abuse.AccountUnlock.MaxVerifyAttemptsPerToken.ShouldBe(5);
        abuse.AccountUnlock.MaxVerifyAttemptsPerIp.ShouldBe(25);
        jwt.RefreshTokenBytes.ShouldBeGreaterThanOrEqualTo(32);
        emailTemplates.AccountVerify.ShouldEndWith(".html");
        emailTemplates.AccountVerificationSuccessPage.ShouldEndWith(".html");
        emailSubjects.AccountVerify.ShouldNotContain(".html");
        emailSubjects.AccountDeleteVerify.ShouldNotContain("email_templates");
        registration.DeleteRequestCooldownMinutes.ShouldBe(15);
        registration.DeleteRequestWindowHours.ShouldBe(24);
        registration.DeleteMaxRequestsPerWindow.ShouldBe((short)8);
        registration.DeleteMaxFinalizeFailures.ShouldBe((short)5);
        registration.DeleteFinalizeLockoutMinutes.ShouldBe(30);
        passwordReset.CodeLength.ShouldBe(8);
        passwordReset.CodeHashPepper.ShouldBe("test-password-reset-code-pepper");
        passwordReset.ExpirationMinutes.ShouldBe(2);
        passwordReset.MaxAttempts.ShouldBe(5);
        passwordReset.RequestCooldownSeconds.ShouldBe(60);
        passwordReset.DailyRequestLimitPerAccount.ShouldBe(5);
        passwordReset.DailyRequestLimitPerDestination.ShouldBe(5);
        passwordReset.DailyRequestLimitPerIp.ShouldBe(20);
        passwordReset.DailyRequestWindowHours.ShouldBe(24);
        passwordReset.RateLimitBlockMinutes.ShouldBe(30);
        passwordReset.CaptchaChallengeEnabled.ShouldBeFalse();
        passwordReset.CaptchaChallengeAfterRequests.ShouldBe(3);
        totp.Issuer.ShouldBe("Treehammock");
        totp.Digits.ShouldBe(6);
        totp.PeriodSeconds.ShouldBe(30);
        totp.AllowedClockSkewSteps.ShouldBe(1);
        totp.HashAlgorithm.ShouldBe("SHA1");
        totp.SecretBytes.ShouldBe(20);
        TotpSettings.TryDecodeProtectionKey(totp.ProtectionKeys[totp.ActiveProtectionKeyId], out byte[] totpKey).ShouldBeTrue();
        totpKey.Length.ShouldBe(32);
        smtp.SMTPQualifiedDomain.ShouldNotBeNullOrWhiteSpace();
        smtp.SMTPPort.ShouldBeGreaterThan(0);
        smtp.SMTPUsername.ShouldNotBeNullOrWhiteSpace();
        smtp.SMTPPassword.ShouldNotBeNullOrWhiteSpace();
        smtp.NoReplyEmailAddress.ShouldContain("@");
        sidewalk.SmsEnabled.ShouldBeTrue();
        sidewalk.AwsSnsEnabled.ShouldBeTrue();
        sidewalk.TwilioEnabled.ShouldBeTrue();
        sidewalk.SmsProviderPrimary.ShouldBe("aws");
        sidewalk.SmsProviderSecondary.ShouldBe("twilio");
        hosting.Port.ShouldBe(5001);
        hosting.UseHttps.ShouldBeTrue();
        hosting.UseHttpsRedirection.ShouldBeTrue();
        hosting.UseForwardedHeaders.ShouldBeFalse();
    }


    [Theory]
    [InlineData("AbuseControlSettings:DragonflyTimeoutMilliseconds", "0")]
    [InlineData("AbuseControlSettings:TwoFactor:MaxAttemptsPerChallenge", "0")]
    [InlineData("AbuseControlSettings:TwoFactor:ChallengeAttemptWindowSeconds", "59")]
    [InlineData("AbuseControlSettings:TwoFactor:MaxSetupVerifyAttemptsPerAccount", "0")]
    [InlineData("AbuseControlSettings:Delivery:MaxSmsDeliveriesPerAccountPerHour", "0")]
    [InlineData("AbuseControlSettings:Delivery:MaxEmailDeliveriesPerIpPerHour", "0")]
    [InlineData("AbuseControlSettings:FailureCooldown:FailureThreshold", "0")]
    [InlineData("AbuseControlSettings:Login:MaxAttemptsPerAccountPerWindow", "0")]
    [InlineData("AbuseControlSettings:Login:MaxAttemptsPerIdentifierPerWindow", "0")]
    [InlineData("AbuseControlSettings:Login:CaptchaChallengeAfterAttempts", "0")]
    [InlineData("AbuseControlSettings:PasswordReset:MaxTokenVerificationAttemptsPerResetId", "0")]
    [InlineData("AbuseControlSettings:PasswordReset:MaxTwoFactorProofAttemptsPerResetId", "0")]
    [InlineData("AbuseControlSettings:PasswordReset:MaxFinalizeAttemptsPerResetId", "0")]
    [InlineData("AbuseControlSettings:AccountUnlock:MaxVerifyAttemptsPerToken", "0")]
    [InlineData("AbuseControlSettings:AccountUnlock:VerifyAttemptWindowSeconds", "1")]
    [InlineData("AbuseControlSettings:AccountDelete:MaxFinalizeAttemptsPerToken", "0")]
    [InlineData("AbuseControlSettings:PublicTokenVerification:MaxVerifyAttemptsPerToken", "0")]
    [InlineData("AbuseControlSettings:Activation:MaxVerifyAttemptsPerAccount", "0")]
    [InlineData("AbuseControlSettings:Activation:VerifyAttemptWindowSeconds", "1")]
    public void Invalid_abuse_control_config_fails_options_validation(string settingKey, string invalidValue)
    {
        var settings = TestConfiguration.ValidSettings();
        settings[settingKey] = invalidValue;

        var services = new ServiceCollection();
        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(settings)
            .Build();

        services.AddTreehammockServices(configuration);

        using ServiceProvider provider = services.BuildServiceProvider();

        var exception = Record.Exception(() => provider.GetRequiredService<IOptions<AbuseControlSettings>>().Value);

        exception.ShouldNotBeNull();
        exception.ShouldBeOfType<OptionsValidationException>();
        exception.Message.ShouldContain("AbuseControlSettings");
    }


    [Theory]
    [InlineData("PasswordResetSettings:CodeLength", "5")]
    [InlineData("PasswordResetSettings:CodeHashPepper", "")]
    [InlineData("PasswordResetSettings:CodeHashPepper", "too-short")]
    [InlineData("PasswordResetSettings:ExpirationMinutes", "0")]
    [InlineData("PasswordResetSettings:ExpirationMinutes", "1")]
    [InlineData("PasswordResetSettings:MaxAttempts", "0")]
    [InlineData("PasswordResetSettings:RequestCooldownSeconds", "3601")]
    [InlineData("PasswordResetSettings:DailyRequestLimitPerAccount", "0")]
    [InlineData("PasswordResetSettings:DailyRequestLimitPerDestination", "0")]
    [InlineData("PasswordResetSettings:DailyRequestLimitPerIp", "0")]
    [InlineData("PasswordResetSettings:DailyRequestWindowHours", "0")]
    [InlineData("PasswordResetSettings:DailyRequestWindowHours", "169")]
    [InlineData("PasswordResetSettings:RateLimitBlockMinutes", "0")]
    [InlineData("PasswordResetSettings:RateLimitBlockMinutes", "1441")]
    [InlineData("PasswordResetSettings:CaptchaChallengeAfterRequests", "0")]
    public void Invalid_password_reset_config_fails_options_validation(string settingKey, string invalidValue)
    {
        var settings = TestConfiguration.ValidSettings();
        settings[settingKey] = invalidValue;

        var services = new ServiceCollection();
        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(settings)
            .Build();

        services.AddTreehammockServices(configuration);

        using ServiceProvider provider = services.BuildServiceProvider();

        var exception = Record.Exception(() => provider.GetRequiredService<IOptions<PasswordResetSettings>>().Value);

        exception.ShouldNotBeNull();
        exception.ShouldBeOfType<OptionsValidationException>();
        exception.Message.ShouldContain("PasswordResetSettings");
    }

    [Theory]
    [InlineData("TotpSettings:Issuer", "")]
    [InlineData("TotpSettings:Digits", "5")]
    [InlineData("TotpSettings:Digits", "9")]
    [InlineData("TotpSettings:PeriodSeconds", "14")]
    [InlineData("TotpSettings:PeriodSeconds", "121")]
    [InlineData("TotpSettings:AllowedClockSkewSteps", "3")]
    [InlineData("TotpSettings:HashAlgorithm", "MD5")]
    [InlineData("TotpSettings:SecretBytes", "19")]
    [InlineData("TotpSettings:SecretBytes", "65")]
    [InlineData("TotpSettings:ProtectionKeys:test", "")]
    [InlineData("TotpSettings:ProtectionKeys:test", "not-base64")]
    public void Invalid_totp_config_fails_options_validation(string settingKey, string invalidValue)
    {
        var settings = TestConfiguration.ValidSettings();
        settings[settingKey] = invalidValue;

        var services = new ServiceCollection();
        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(settings)
            .Build();

        services.AddTreehammockServices(configuration);

        using ServiceProvider provider = services.BuildServiceProvider();

        var exception = Record.Exception(() => provider.GetRequiredService<IOptions<TotpSettings>>().Value);

        exception.ShouldNotBeNull();
        exception.ShouldBeOfType<OptionsValidationException>();
        exception.Message.ShouldContain("TotpSettings");
    }

    [Fact]
    public void Enabled_sms_without_enabled_provider_flags_fails_options_validation()
    {
        var settings = TestConfiguration.ValidSettings();
        settings["SidewalkSettings:SmsEnabled"] = "true";
        settings["SidewalkSettings:AwsSnsEnabled"] = "false";
        settings["SidewalkSettings:TwilioEnabled"] = "false";

        var services = new ServiceCollection();
        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(settings)
            .Build();

        services.AddTreehammockServices(configuration);

        using ServiceProvider provider = services.BuildServiceProvider();

        var exception = Record.Exception(() => provider.GetRequiredService<IOptions<SidewalkSettings>>().Value);

        exception.ShouldNotBeNull();
        exception.ShouldBeOfType<OptionsValidationException>();
        exception.Message.ShouldContain("SidewalkSettings");
    }


    [Theory]
    [InlineData("carrier-pigeon", "twilio", true, true)]
    [InlineData("aws", "twilio", false, true)]
    [InlineData("aws", "twilio", true, false)]
    [InlineData("aws", "sns", true, true)]
    public void Invalid_sms_provider_routing_fails_options_validation(
        string primaryProvider,
        string? secondaryProvider,
        bool awsEnabled,
        bool twilioEnabled)
    {
        var settings = TestConfiguration.ValidSettings();
        settings["SidewalkSettings:SmsEnabled"] = "true";
        settings["SidewalkSettings:AwsSnsEnabled"] = awsEnabled.ToString();
        settings["SidewalkSettings:TwilioEnabled"] = twilioEnabled.ToString();
        settings["SidewalkSettings:SmsProviderPrimary"] = primaryProvider;
        settings["SidewalkSettings:SmsProviderSecondary"] = secondaryProvider;

        var services = new ServiceCollection();
        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(settings)
            .Build();

        services.AddTreehammockServices(configuration);

        using ServiceProvider provider = services.BuildServiceProvider();

        var exception = Record.Exception(() => provider.GetRequiredService<IOptions<SidewalkSettings>>().Value);

        exception.ShouldNotBeNull();
        exception.ShouldBeOfType<OptionsValidationException>();
        exception.Message.ShouldContain("SidewalkSettings");
    }

    [Theory]
    [InlineData("aws", "twilio")]
    [InlineData("sns", "twilio")]
    [InlineData("aws-sns", "twilio")]
    public void Valid_sms_provider_aliases_pass_options_validation(string primaryProvider, string secondaryProvider)
    {
        var settings = TestConfiguration.ValidSettings();
        settings["SidewalkSettings:SmsEnabled"] = "true";
        settings["SidewalkSettings:AwsSnsEnabled"] = "true";
        settings["SidewalkSettings:TwilioEnabled"] = "true";
        settings["SidewalkSettings:SmsProviderPrimary"] = primaryProvider;
        settings["SidewalkSettings:SmsProviderSecondary"] = secondaryProvider;

        var services = new ServiceCollection();
        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(settings)
            .Build();

        services.AddTreehammockServices(configuration);

        using ServiceProvider provider = services.BuildServiceProvider();

        var exception = Record.Exception(() => provider.GetRequiredService<IOptions<SidewalkSettings>>().Value);

        exception.ShouldBeNull();
    }

    [Fact]
    public void Jwt_settings_do_not_expose_configurable_session_concurrency_modes()
    {
        typeof(JWTSettings).GetProperty("SessionConcurrencyMode").ShouldBeNull();
    }

    [Fact]
    public void Invalid_zero_token_periods_fail_registration_options_validation()
    {
        var settings = TestConfiguration.ValidSettings();
        settings["RegistrationSettings:VerifyAccountPeriodWeeks"] = "0";
        settings["RegistrationSettings:VerifyAccountPeriodDays"] = "0";
        settings["RegistrationSettings:VerifyAccountPeriodHours"] = "0";
        settings["RegistrationSettings:EmailChangeVerifyPeriodWeeks"] = "0";
        settings["RegistrationSettings:EmailChangeVerifyPeriodDays"] = "0";
        settings["RegistrationSettings:EmailChangeVerifyPeriodHours"] = "0";
        settings["RegistrationSettings:AccountDeleteTokenPeriodWeeks"] = "0";
        settings["RegistrationSettings:AccountDeleteTokenPeriodDays"] = "0";
        settings["RegistrationSettings:AccountDeleteTokenPeriodHours"] = "0";

        var services = new ServiceCollection();
        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(settings)
            .Build();

        services.AddTreehammockServices(configuration);

        using ServiceProvider provider = services.BuildServiceProvider();

        var exception = Record.Exception(() => provider.GetRequiredService<IOptions<RegistrationSettings>>().Value);

        exception.ShouldNotBeNull();
        exception.ShouldBeOfType<OptionsValidationException>();
        exception.Message.ShouldContain("RegistrationSettings");
    }
}
