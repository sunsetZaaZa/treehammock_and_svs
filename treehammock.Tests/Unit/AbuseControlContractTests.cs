using System.ComponentModel.DataAnnotations;
using System.Reflection;
using Shouldly;

using treehammock.Rigging.Abuse;
using treehammock.Rigging.Config;
using treehammock.Services;

namespace treehammock.Tests.Unit;

public class AbuseControlContractTests
{
    [Fact]
    public void Abuse_control_settings_enable_required_policies_by_default()
    {
        var settings = new AbuseControlSettings();
        var results = new List<ValidationResult>();

        bool valid = Validator.TryValidateObject(
            settings,
            new ValidationContext(settings),
            results,
            validateAllProperties: true);

        valid.ShouldBeTrue(string.Join(Environment.NewLine, results.Select(result => result.ErrorMessage)));
        settings.Enabled.ShouldBeTrue();
        settings.TwoFactor.Enabled.ShouldBeTrue();
        settings.Delivery.Enabled.ShouldBeTrue();
        settings.FailureCooldown.Enabled.ShouldBeTrue();
        settings.Login.Enabled.ShouldBeTrue();
        settings.Login.MaxAttemptsPerIdentifierPerWindow.ShouldBe(10);
        settings.Login.CaptchaChallengeEnabled.ShouldBeFalse();
        settings.Login.CaptchaChallengeAfterAttempts.ShouldBe(5);
        settings.PasswordReset.Enabled.ShouldBeTrue();
        settings.PasswordReset.MaxRequestsPerIdentifierPerHour.ShouldBe(5);
        settings.PasswordReset.MaxTokenVerificationAttemptsPerResetId.ShouldBe(5);
        settings.PasswordReset.MaxTwoFactorProofAttemptsPerResetId.ShouldBe(5);
        settings.PasswordReset.MaxFinalizeAttemptsPerResetId.ShouldBe(5);
        settings.AccountUnlock.Enabled.ShouldBeTrue();
        settings.AccountUnlock.MaxVerifyAttemptsPerToken.ShouldBe(5);
        settings.AccountUnlock.MaxVerifyAttemptsPerIp.ShouldBe(25);
        settings.AccountDelete.Enabled.ShouldBeTrue();
        settings.AccountDelete.MaxFinalizeAttemptsPerAccount.ShouldBe(5);
        settings.AccountDelete.MaxFinalizeAttemptsPerToken.ShouldBe(5);
        settings.PublicTokenVerification.Enabled.ShouldBeTrue();
        settings.PublicTokenVerification.MaxVerifyAttemptsPerToken.ShouldBe(10);
        settings.PublicTokenVerification.MaxVerifyAttemptsPerIp.ShouldBe(100);
        settings.Activation.Enabled.ShouldBeTrue();
        settings.Activation.MaxVerifyAttemptsPerAccount.ShouldBe(5);
        settings.Activation.MaxVerifyAttemptsPerIdentifier.ShouldBe(5);
        settings.Activation.MaxVerifyAttemptsPerIp.ShouldBe(50);
        settings.AuthenticatedMutationIdempotency.Enabled.ShouldBeTrue();
        settings.AuthenticatedMutationIdempotency.MinKeyLength.ShouldBe(16);
        settings.AuthenticatedMutationIdempotency.MaxKeyLength.ShouldBe(128);
        settings.AuthenticatedMutationIdempotency.InProgressTtlSeconds.ShouldBe(600);
        settings.AuthenticatedMutationIdempotency.CompletedTtlSeconds.ShouldBe(900);
        settings.CounterFailureMode.ShouldBe(AbuseCounterFailureMode.FailClosed);
    }

    [Fact]
    public void Abuse_control_settings_validate_nested_policy_ranges()
    {
        var settings = new AbuseControlSettings
        {
            TwoFactor = new TwoFactorAbusePolicySettings { MaxAttemptsPerChallenge = 0 },
            Delivery = new DeliveryAbusePolicySettings { MaxSmsDeliveriesPerAccountPerHour = 0 },
            FailureCooldown = new FailureCooldownSettings { FailureThreshold = 0 },
            Login = new LoginAbusePolicySettings { WindowSeconds = 1 },
            PasswordReset = new PasswordResetAbusePolicySettings { MaxTokenVerificationAttemptsPerResetId = 0 },
            AccountUnlock = new AccountUnlockAbusePolicySettings { MaxVerifyAttemptsPerToken = 0 },
            AccountDelete = new AccountDeleteAbusePolicySettings { MaxFinalizeAttemptsPerToken = 0 },
            PublicTokenVerification = new PublicTokenVerificationAbusePolicySettings { MaxVerifyAttemptsPerToken = 0 },
            Activation = new ActivationAbusePolicySettings { MaxVerifyAttemptsPerAccount = 0 },
            AuthenticatedMutationIdempotency = new AuthenticatedMutationIdempotencySettings { InProgressTtlSeconds = 1 },
            DragonflyTimeoutMilliseconds = 10
        };
        var results = new List<ValidationResult>();

        bool valid = Validator.TryValidateObject(
            settings,
            new ValidationContext(settings),
            results,
            validateAllProperties: true);

        valid.ShouldBeFalse();
        results.Select(result => result.ErrorMessage ?? string.Empty)
            .ShouldContain(message => message.Contains("TwoFactor", StringComparison.Ordinal));
        results.Select(result => result.ErrorMessage ?? string.Empty)
            .ShouldContain(message => message.Contains("Delivery", StringComparison.Ordinal));
        results.Select(result => result.ErrorMessage ?? string.Empty)
            .ShouldContain(message => message.Contains("FailureCooldown", StringComparison.Ordinal));
        results.Select(result => result.ErrorMessage ?? string.Empty)
            .ShouldContain(message => message.Contains("Login", StringComparison.Ordinal));
        results.Select(result => result.ErrorMessage ?? string.Empty)
            .ShouldContain(message => message.Contains("PasswordReset", StringComparison.Ordinal));
        results.Select(result => result.ErrorMessage ?? string.Empty)
            .ShouldContain(message => message.Contains("AccountUnlock", StringComparison.Ordinal));
        results.Select(result => result.ErrorMessage ?? string.Empty)
            .ShouldContain(message => message.Contains("AccountDelete", StringComparison.Ordinal));
        results.Select(result => result.ErrorMessage ?? string.Empty)
            .ShouldContain(message => message.Contains("PublicTokenVerification", StringComparison.Ordinal));
        results.Select(result => result.ErrorMessage ?? string.Empty)
            .ShouldContain(message => message.Contains("Activation", StringComparison.Ordinal));
        results.Select(result => result.ErrorMessage ?? string.Empty)
            .ShouldContain(message => message.Contains("AuthenticatedMutationIdempotency", StringComparison.Ordinal));
    }

    [Fact]
    public void Safe_abuse_identifier_stores_only_kind_length_and_fingerprint()
    {
        var identifier = new SafeAbuseIdentifier("Email", 18, "ABC123DEF456");

        identifier.Kind.ShouldBe("email");
        identifier.Length.ShouldBe(18);
        identifier.Fingerprint.ShouldBe("abc123def456");
    }

    [Theory]
    [InlineData("", 5, "abc")]
    [InlineData("email", -1, "abc")]
    [InlineData("email", 5, "")]
    [InlineData("email:raw", 5, "abc")]
    [InlineData("email", 5, "raw value")]
    public void Safe_abuse_identifier_rejects_unsafe_segments(string kind, int length, string fingerprint)
    {
        Exception? exception = Record.Exception(() => _ = new SafeAbuseIdentifier(kind, length, fingerprint));

        exception.ShouldNotBeNull();
        typeof(ArgumentException).IsAssignableFrom(exception.GetType()).ShouldBeTrue();
    }

    [Fact]
    public void Abuse_counter_key_uses_namespaced_safe_segments()
    {
        var key = new AbuseCounterKey(
            AbuseFeature.PasswordResetFinalize,
            AbuseCounterDimension.Reset,
            "9f3a6c");

        key.Value.ShouldBe("abuse:passwordresetfinalize:reset:9f3a6c");
        key.CooldownValue.ShouldBe("abuse:cooldown:passwordresetfinalize:reset:9f3a6c");
        key.ToString().ShouldBe(key.Value);
    }

    [Theory]
    [InlineData(0, 60, null)]
    [InlineData(1, 0, null)]
    [InlineData(1, 60, -1)]
    public void Abuse_counter_limit_rejects_invalid_bounds(int maxAttempts, int windowSeconds, int? cooldownSeconds)
    {
        Exception? exception = Record.Exception(() => _ = new AbuseCounterLimit(
            maxAttempts,
            TimeSpan.FromSeconds(windowSeconds),
            cooldownSeconds is null ? null : TimeSpan.FromSeconds(cooldownSeconds.Value)));

        exception.ShouldNotBeNull();
        exception.ShouldBeOfType<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void Abuse_contract_models_do_not_expose_raw_identifier_or_secret_fields()
    {
        Type[] types =
        [
            typeof(AbusePolicyRequest),
            typeof(AbuseEventRecord),
            typeof(SafeAbuseIdentifier),
            typeof(AbuseCounterKey),
            typeof(AbuseDecision),
            typeof(CounterDecision),
            typeof(CooldownDecision),
            typeof(DeliveryAbuseThrottleRequest)
        ];

        string[] forbiddenFragments =
        [
            "EmailAddress",
            "PhoneNumber",
            "Username",
            "Raw",
            "Password",
            "Token",
            "Secret"
        ];

        foreach (Type type in types)
        {
            IEnumerable<string> propertyNames = type
                .GetProperties(BindingFlags.Public | BindingFlags.Instance)
                .Select(property => property.Name);

            foreach (string propertyName in propertyNames)
            {
                foreach (string forbidden in forbiddenFragments)
                {
                    propertyName.ShouldNotContain(forbidden, Case.Insensitive);
                }
            }
        }
    }

    [Fact]
    public void Abuse_reason_codes_are_stable_uppercase_constants()
    {
        string[] codes = typeof(AbuseReasonCodes)
            .GetFields(BindingFlags.Public | BindingFlags.Static | BindingFlags.FlattenHierarchy)
            .Where(field => field.IsLiteral && !field.IsInitOnly && field.FieldType == typeof(string))
            .Select(field => (string)field.GetRawConstantValue()!)
            .ToArray();

        codes.ShouldNotBeEmpty();
        codes.ShouldAllBe(code => code.StartsWith("ABUSE_", StringComparison.Ordinal));
        codes.ShouldAllBe(code => code == code.ToUpperInvariant());
        codes.Distinct(StringComparer.Ordinal).Count().ShouldBe(codes.Length);
    }
}
