using System.Reflection;
using System.Security.Cryptography;
using System.Text;

using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NodaTime;
using Shouldly;

using treehammock.Repos;
using treehammock.Rigging.Config;
using treehammock.RiggingSupport.Enum;
using treehammock.Services;

namespace treehammock.Tests.Unit;

public class AuthenticatorAppProvisioningServiceTests
{
    private static treehammock.DataLayer.Security.SensitiveActionGrant TestGrant(string label)
        => new("test-session", "test-token", "test-target", treehammock.Rigging.Security.SensitiveActionTargets.AuthenticatorSetup(label, true, TotpProviderType.LOCAL_RFC6238));

    [Fact]
    public void Base32_encoder_emits_rfc4648_uppercase_without_padding()
    {
        var encoder = new AuthenticatorAppBase32Encoder();

        encoder.Encode("foo"u8.ToArray()).ShouldBe("MZXW6");
        encoder.Encode("1234567890"u8.ToArray()).ShouldBe("GEZDGNBVGY3TQOJQ");
    }

    [Fact]
    public void Provisioning_uri_builder_emits_standard_otpauth_uri()
    {
        TotpSettings settings = Settings();
        var builder = new AuthenticatorAppProvisioningUriBuilder(Options.Create(settings));

        string uri = builder.Build(new AuthenticatorAppProvisioningUriCommand("reader@example.com", "JBSWY3DPEHPK3PXP"));

        uri.ShouldStartWith("otpauth://totp/Treehammock%3Areader%40example.com");
        uri.ShouldContain("secret=JBSWY3DPEHPK3PXP");
        uri.ShouldContain("issuer=Treehammock");
        uri.ShouldContain("algorithm=SHA1");
        uri.ShouldContain("digits=6");
        uri.ShouldContain("period=30");
    }

    [Fact]
    public void Local_provider_creates_manual_key_and_uri_for_standard_authenticator_apps()
    {
        TotpSettings settings = Settings(secretBytes: 20);
        var provider = LocalProvider(settings);

        AuthenticatorAppProvisioningMaterial material = provider.CreateProvisioningMaterial("reader@example.com", "My phone");

        material.ProviderType.ShouldBe(TotpProviderType.LOCAL_RFC6238);
        material.Secret.Length.ShouldBe(settings.SecretBytes);
        material.ManualEntryKey.ShouldNotBeNullOrWhiteSpace();
        material.ManualEntryKey.ShouldNotContain("=");
        material.ManualEntryKey.ShouldBe(material.ManualEntryKey.ToUpperInvariant());
        material.OtpauthUri.ShouldStartWith("otpauth://totp/");
        material.OtpauthUri.ShouldContain("issuer=Treehammock");
        material.OtpauthUri.ShouldContain("algorithm=SHA1");
    }

    [Fact]
    public void Provider_registry_uses_local_rfc6238_as_default_provider()
    {
        ITotpProvider localProvider = LocalProvider(Settings());
        var registry = new TotpProviderRegistry([localProvider]);

        registry.DefaultProvider.ShouldBeSameAs(localProvider);
        registry.GetRequiredProvider(TotpProviderType.LOCAL_RFC6238).ShouldBeSameAs(localProvider);
    }

    [Fact]
    public async Task Setup_service_protects_secret_and_stores_only_token_hash_in_sql_command()
    {
        TotpSettings settings = Settings();
        var repo = new CapturingEnrollmentRepo
        {
            BeginResult = new AuthenticatorAppSetupBeginCommandResult(
                true,
                AuthenticatorAppSetupService.SetupStartedCode,
                1,
                Instant.FromUnixTimeSeconds(1_700_000_600))
        };
        var service = SetupService(settings, repo);

        StartAuthenticatorAppSetupResult result = await service.StartSetupAsync(new StartAuthenticatorAppSetupCommand(
            Guid.NewGuid(),
            Guid.NewGuid(),
            "reader@example.com",
            "My phone",
            Required: true, Grant: TestGrant("My phone")));

        result.Succeeded.ShouldBeTrue();
        result.SetupId.ShouldNotBeNullOrWhiteSpace();
        result.ManualEntryKey.ShouldNotBeNullOrWhiteSpace();
        result.OtpauthUri.ShouldNotBeNullOrWhiteSpace();
        result.ProviderType.ShouldBe(TotpProviderType.LOCAL_RFC6238);

        repo.BeginCalled.ShouldBeTrue();
        BeginAuthenticatorAppSetupCommand command = repo.LastBeginCommand.ShouldNotBeNull();
        command.SetupTokenHash.ShouldNotBe(result.SetupId);
        command.TotpSecretCiphertext.ShouldNotBeNull();
        command.TotpSecretNonce.ShouldNotBeNull();
        command.TotpSecretTag.ShouldNotBeNull();
        command.TotpSecretVersion.ShouldBe(TotpSecretProtector.CurrentVersion);
        command.TotpKeyId.ShouldBe(settings.ActiveProtectionKeyId);
        command.Context.ShouldNotBeNull();
        command.Context.AccountId.ShouldBe(command.AccountId);
        command.Context.EnrollmentId.ShouldNotBe(Guid.Empty);
        command.Context.Parameters.ShouldBe(TotpParameters.FromDefaults(settings));
        command.TotpProviderType.ShouldBe(TotpProviderType.LOCAL_RFC6238);
        command.TotpSecretCiphertext!.Length.ShouldBe(settings.SecretBytes);
        command.TotpSecretNonce!.Length.ShouldBe(TotpSecretProtector.NonceSizeBytes);
        command.TotpSecretTag!.Length.ShouldBe(TotpSecretProtector.TagSizeBytes);
    }


    [Fact]
    public async Task Setup_service_returns_already_attached_code_without_secret_material_when_repo_rejects_duplicate()
    {
        var repo = new CapturingEnrollmentRepo
        {
            BeginResult = new AuthenticatorAppSetupBeginCommandResult(
                false,
                AuthenticatorAppSetupService.AuthenticatorAppAlreadyAttachedCode,
                null,
                null)
        };
        var service = SetupService(Settings(), repo);

        StartAuthenticatorAppSetupResult result = await service.StartSetupAsync(new StartAuthenticatorAppSetupCommand(
            Guid.NewGuid(),
            Guid.NewGuid(),
            "reader@example.com",
            "Existing phone",
            Required: true, Grant: TestGrant("Existing phone")));

        result.Succeeded.ShouldBeFalse();
        result.Code.ShouldBe(AuthenticatorAppSetupService.AuthenticatorAppAlreadyAttachedCode);
        result.SetupId.ShouldBeNull();
        result.OtpauthUri.ShouldBeNull();
        result.ManualEntryKey.ShouldBeNull();
        repo.BeginCalled.ShouldBeTrue();
    }

    [Fact]
    public async Task Setup_service_rejects_managed_provider_until_dedicated_provider_contract_exists()
    {
        var repo = new CapturingEnrollmentRepo();
        var service = SetupService(Settings(), repo);

        StartAuthenticatorAppSetupResult result = await service.StartSetupAsync(new StartAuthenticatorAppSetupCommand(
            Guid.NewGuid(),
            Guid.NewGuid(),
            "reader@example.com",
            null,
            Required: true,
            ProviderType: TotpProviderType.TWILIO_VERIFY_TOTP));

        result.Succeeded.ShouldBeFalse();
        result.Code.ShouldBe(AuthenticatorAppSetupService.UnsupportedProviderCode);
        repo.BeginCalled.ShouldBeFalse();
    }


    [Fact]
    public async Task Setup_service_cancels_pending_setup_using_hashed_setup_id()
    {
        var repo = new CapturingEnrollmentRepo
        {
            CancelResult = new AuthenticatorAppSetupCancelCommandResult(true, AuthenticatorAppSetupService.SetupCancelledCode)
        };
        var service = SetupService(Settings(), repo);

        CancelAuthenticatorAppSetupResult result = await service.CancelSetupAsync(new CancelAuthenticatorAppSetupServiceCommand(
            Guid.NewGuid(),
            Guid.NewGuid(),
            "raw-setup-id"));

        result.Succeeded.ShouldBeTrue();
        repo.CancelCalled.ShouldBeTrue();
        repo.LastCancelCommand.ShouldNotBeNull();
        repo.LastCancelCommand!.SetupTokenHash.ShouldNotBe("raw-setup-id");
    }

    [Fact]
    public async Task Setup_service_records_failure_when_setup_totp_is_invalid()
    {
        TotpSettings settings = Settings();
        var protector = new TotpSecretProtector(Options.Create(settings));
        byte[] secret = RandomNumberGenerator.GetBytes(settings.SecretBytes);
        Guid accountId = Guid.NewGuid();
        ProtectedTotpSecret protectedSecret = protector.Protect(secret, new(accountId, Guid.NewGuid(), TotpParameters.FromDefaults(settings)));
        var repo = new CapturingEnrollmentRepo
        {
            PendingResult = new PendingAuthenticatorAppSetupRecord(
                true,
                "AUTHENTICATOR_SETUP_PENDING",
                1,
                SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(10)),
                0,
                protectedSecret.Ciphertext,
                protectedSecret.Nonce,
                protectedSecret.Tag,
                protectedSecret.Version,
                null,
                (short)TotpProviderType.LOCAL_RFC6238, protectedSecret.KeyId, protectedSecret.Context, 1),
            FailureResult = new AuthenticatorAppSetupFailureCommandResult(false, "AUTHENTICATOR_SETUP_INCORRECT", 1, null)
        };
        var service = SetupService(settings, repo);

        VerifyAuthenticatorAppSetupAndRotateSessionResult result = await service.VerifySetupAndRotateSessionAsync(
            new VerifyAuthenticatorAppSetupAndRotateSessionCommand(
                accountId,
                Guid.NewGuid(),
                "raw-setup-id",
                "abc",
                "old-access-hash",
                "new-access-hash",
                RandomNumberGenerator.GetBytes(64),
                0,
                0,
                SystemClock.Instance.GetCurrentInstant(),
                Period.FromHours(1),
                SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(15)),
                SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromHours(1)),
                null,
                FeatureSet.basic,
                Guid.NewGuid()));

        result.Succeeded.ShouldBeFalse();
        repo.PendingCalled.ShouldBeTrue();
        repo.FailureCalled.ShouldBeTrue();
        repo.CompleteCalled.ShouldBeFalse();
    }


    [Fact]
    public async Task Setup_service_completes_valid_totp_by_calling_atomic_rotation_contract()
    {
        TotpSettings settings = Settings();
        var protector = new TotpSecretProtector(Options.Create(settings));
        byte[] secret = "12345678901234567890"u8.ToArray();
        Guid accountId = Guid.NewGuid();
        ProtectedTotpSecret protectedSecret = protector.Protect(secret, new(accountId, Guid.NewGuid(), TotpParameters.FromDefaults(settings)));
        Instant now = Instant.FromUnixTimeSeconds(1_700_000_000);
        long step = now.ToUnixTimeSeconds() / settings.PeriodSeconds;
        string code = TotpCodeVerifier.ComputeCode(secret, step, settings.Digits, settings.HashAlgorithm);
        Guid newAccountSecurityStamp = Guid.NewGuid();
        Guid sessionSecurityStamp = Guid.NewGuid();
        byte[] refreshToken = RandomNumberGenerator.GetBytes(64);
        var repo = new CapturingEnrollmentRepo
        {
            PendingResult = new PendingAuthenticatorAppSetupRecord(
                true,
                "AUTHENTICATOR_SETUP_PENDING",
                1,
                now.Plus(Duration.FromMinutes(10)),
                0,
                protectedSecret.Ciphertext,
                protectedSecret.Nonce,
                protectedSecret.Tag,
                protectedSecret.Version,
                null,
                (short)TotpProviderType.LOCAL_RFC6238, protectedSecret.KeyId, protectedSecret.Context, 1),
            CompleteResult = new AuthenticatorAppSetupCompletionCommandResult(
                true,
                AuthenticatorAppSetupService.SetupVerifiedSessionRotatedCode,
                newAccountSecurityStamp,
                1)
        };
        var service = SetupService(settings, repo);

        VerifyAuthenticatorAppSetupAndRotateSessionResult result = await service.VerifySetupAndRotateSessionAsync(
            new VerifyAuthenticatorAppSetupAndRotateSessionCommand(
                accountId,
                Guid.NewGuid(),
                "raw-setup-id",
                code,
                "old-access-hash",
                "new-access-hash",
                refreshToken,
                0,
                0,
                now,
                Period.FromHours(1),
                now.Plus(Duration.FromMinutes(15)),
                now.Plus(Duration.FromHours(1)),
                null,
                FeatureSet.basic,
                sessionSecurityStamp));

        result.Succeeded.ShouldBeTrue();
        result.Code.ShouldBe(AuthenticatorAppSetupService.SetupVerifiedSessionRotatedCode);
        result.NewAccountSecurityStamp.ShouldBe(newAccountSecurityStamp);
        repo.PendingCalled.ShouldBeTrue();
        repo.FailureCalled.ShouldBeFalse();
        repo.CompleteCalled.ShouldBeTrue();
        CompleteAuthenticatorAppSetupAndRotateSessionCommand command = repo.LastCompleteCommand.ShouldNotBeNull();
        command.SetupTokenHash.ShouldNotBe("raw-setup-id");
        command.TimeStep.ShouldBe(step);
        command.ExpectedOldAccessTokenHash.ShouldBe("old-access-hash");
        command.NewAccessTokenHash.ShouldBe("new-access-hash");
        command.RefreshToken.ShouldBe(refreshToken);
        command.SessionSecurityStamp.ShouldBe(sessionSecurityStamp);
        command.AccessExpiration.ShouldBe(now.Plus(Duration.FromMinutes(15)));
        command.SessionExpiration.ShouldBe(now.Plus(Duration.FromHours(1)));
    }

    [Fact]
    public void Setup_result_model_does_not_expose_raw_binary_secret()
    {
        PropertyInfo[] properties = typeof(StartAuthenticatorAppSetupResult).GetProperties();

        properties.Any(property => property.PropertyType == typeof(byte[])).ShouldBeFalse();
        properties.Any(property => property.Name.Contains("Secret", StringComparison.OrdinalIgnoreCase)).ShouldBeFalse();
    }

    private static AuthenticatorAppSetupService SetupService(TotpSettings settings, IAuthenticatorAppEnrollmentRepo repo)
    {
        ITotpProvider provider = LocalProvider(settings);
        var registry = new TotpProviderRegistry([provider]);
        var protector = new TotpSecretProtector(Options.Create(settings));

        return new AuthenticatorAppSetupService(
            repo,
            registry,
            protector,
            new TotpCodeVerifier(),
            Options.Create(settings),
            NullLogger<AuthenticatorAppSetupService>.Instance);
    }

    private static LocalTotpProvider LocalProvider(TotpSettings settings)
    {
        var options = Options.Create(settings);
        return new LocalTotpProvider(
            new AuthenticatorAppSecretGenerator(options),
            new AuthenticatorAppBase32Encoder(),
            new AuthenticatorAppProvisioningUriBuilder(options),
            options);
    }

    private static TotpSettings Settings(int secretBytes = 20)
    {
        return new TotpSettings
        {
            Issuer = "Treehammock",
            Digits = 6,
            PeriodSeconds = 30,
            AllowedClockSkewSteps = 1,
            HashAlgorithm = "SHA1",
            SecretBytes = secretBytes,
            ActiveProtectionKeyId = "test", ProtectionKeys = new() { ["test"] = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)) },
            SetupIdBytes = 32,
            SetupExpirationMinutes = 10,
            SetupMaxAttempts = 5
        };
    }

    private sealed class CapturingEnrollmentRepo : IAuthenticatorAppEnrollmentRepo
    {
        public bool BeginCalled { get; private set; }
        public bool PendingCalled { get; private set; }
        public bool FailureCalled { get; private set; }
        public bool CompleteCalled { get; private set; }
        public bool CancelCalled { get; private set; }
        public BeginAuthenticatorAppSetupCommand? LastBeginCommand { get; private set; }
        public GetPendingAuthenticatorAppSetupCommand? LastPendingCommand { get; private set; }
        public RecordAuthenticatorAppSetupFailureCommand? LastFailureCommand { get; private set; }
        public CompleteAuthenticatorAppSetupAndRotateSessionCommand? LastCompleteCommand { get; private set; }
        public CancelAuthenticatorAppSetupCommand? LastCancelCommand { get; private set; }
        public AuthenticatorAppSetupBeginCommandResult? BeginResult { get; set; }
        public PendingAuthenticatorAppSetupRecord? PendingResult { get; set; }
        public AuthenticatorAppSetupFailureCommandResult? FailureResult { get; set; }
        public AuthenticatorAppSetupCompletionCommandResult? CompleteResult { get; set; }
        public AuthenticatorAppSetupCancelCommandResult? CancelResult { get; set; }

        public Task<AuthenticatorAppSetupBeginCommandResult?> BeginAuthenticatorAppSetupAsync(
            BeginAuthenticatorAppSetupCommand command,
            CancellationToken cancellationToken = default)
        {
            BeginCalled = true;
            LastBeginCommand = command with
            {
                TotpSecretCiphertext = command.TotpSecretCiphertext?.ToArray(),
                TotpSecretNonce = command.TotpSecretNonce?.ToArray(),
                TotpSecretTag = command.TotpSecretTag?.ToArray()
            };

            return Task.FromResult(BeginResult);
        }

        public Task<PendingAuthenticatorAppSetupRecord?> GetPendingAuthenticatorAppSetupAsync(GetPendingAuthenticatorAppSetupCommand command, CancellationToken cancellationToken = default)
        {
            PendingCalled = true;
            LastPendingCommand = command;
            return Task.FromResult(PendingResult);
        }

        public Task<AuthenticatorAppSetupFailureCommandResult?> RecordAuthenticatorAppSetupFailureAsync(RecordAuthenticatorAppSetupFailureCommand command, CancellationToken cancellationToken = default)
        {
            FailureCalled = true;
            LastFailureCommand = command;
            return Task.FromResult(FailureResult);
        }

        public Task<AuthenticatorAppSetupCompletionCommandResult?> CompleteAuthenticatorAppSetupAndRotateSessionAsync(CompleteAuthenticatorAppSetupAndRotateSessionCommand command, CancellationToken cancellationToken = default)
        {
            CompleteCalled = true;
            LastCompleteCommand = command;
            return Task.FromResult(CompleteResult);
        }

        public Task<AuthenticatorAppSetupCancelCommandResult?> CancelAuthenticatorAppSetupAsync(CancelAuthenticatorAppSetupCommand command, CancellationToken cancellationToken = default)
        {
            CancelCalled = true;
            LastCancelCommand = command;
            return Task.FromResult(CancelResult);
        }

        public Task<VerifiedTotpEnrollmentRecord?> GetVerifiedTotpEnrollmentForAccountAsync(Guid accountId, Instant now, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<TotpStepReplayCommandResult?> MarkTotpStepUsedAsync(Guid accountId, long twoFactorIndex, long timeStep, Guid enrollmentId, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }
    }
}
