using NSubstitute;
using treehammock.Rigging.Dependencies;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NodaTime;
using Npgsql;
using Shouldly;

using treehammock.Repos;
using treehammock.Rigging.Config;
using treehammock.RiggingSupport.Actions.Account;
using treehammock.Rigging.Database;
using treehammock.Rigging.Security;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;

namespace treehammock.Tests.Unit;

public class RepositoryFailureBoundaryTests
{
    [Fact]
    public async Task Account_repo_throws_typed_dependency_failure_when_connection_open_fails()
    {
        using var storage = new ThrowingStorageContext();
        var repo = new AccountRepo(new treehammock.Rigging.Delivery.DeliveryPayloadProtector(Options.Create(new treehammock.Rigging.Config.DeliveryOutboxSettings {EncryptionKeys=new() {{1,Convert.ToBase64String(new byte[32])}}})),
            storage,
            Options.Create(new JWTSettings()),
            NullLogger<AccountRepo>.Instance,
            CreateUserSecretHasher());

        bool? result = true;
        Exception? exception = await Record.ExceptionAsync(async () =>
        {
            result = await repo.StartAccountVerification(Guid.NewGuid(), 1, cancellationToken: CancellationToken.None);
        });

        exception.ShouldBeOfType<DependencyUnavailableException>();
    }

    [Fact]
    public async Task Account_setup_throws_typed_creation_dependency_failure_when_connection_open_fails()
    {
        using var storage = new ThrowingStorageContext();
        var repo = new AccountRepo(new treehammock.Rigging.Delivery.DeliveryPayloadProtector(Options.Create(new treehammock.Rigging.Config.DeliveryOutboxSettings {EncryptionKeys=new() {{1,Convert.ToBase64String(new byte[32])}}})),
            storage,
            Options.Create(new JWTSettings()),
            NullLogger<AccountRepo>.Instance,
            CreateUserSecretHasher());

        (long? verificationIndex, HttpMessage message, string? detail) result = (1, HttpMessage.ACCOUNT_CREATION_SUCCESSED, "unexpected");
        Exception? exception = await Record.ExceptionAsync(async () =>
        {
            result = await repo.SetupAccount(null!, "verify-token", Period.FromDays(1), AccountSetupAction.EMAIL, null!, cancellationToken: CancellationToken.None);
        });

        exception.ShouldBeOfType<DependencyUnavailableException>();
    }

    [Fact]
    public async Task Account_repo_credential_lookup_throws_typed_failure_when_connection_open_fails()
    {
        using var storage = new ThrowingStorageContext();
        var repo = new AccountRepo(new treehammock.Rigging.Delivery.DeliveryPayloadProtector(Options.Create(new treehammock.Rigging.Config.DeliveryOutboxSettings {EncryptionKeys=new() {{1,Convert.ToBase64String(new byte[32])}}})),
            storage,
            Options.Create(new JWTSettings()),
            NullLogger<AccountRepo>.Instance,
            CreateUserSecretHasher());

        CredentialLookupResult result = CredentialLookupResult.NotFound();
        Exception? exception = await Record.ExceptionAsync(async () =>
        {
            result = await repo.GetCredentials(
                new treehammock.Models.Authentication.AuthenticateLogin("reader@example.com", "Password123!"),
                AccountLoginAction.EMAIL, cancellationToken: CancellationToken.None);
        });

        exception.ShouldBeOfType<DependencyUnavailableException>();
    }


    [Fact]
    public async Task Account_repo_two_factor_details_lookup_throws_typed_failure_when_connection_open_fails()
    {
        using var storage = new ThrowingStorageContext();
        var repo = new AccountRepo(new treehammock.Rigging.Delivery.DeliveryPayloadProtector(Options.Create(new treehammock.Rigging.Config.DeliveryOutboxSettings {EncryptionKeys=new() {{1,Convert.ToBase64String(new byte[32])}}})),
            storage,
            Options.Create(new JWTSettings()),
            NullLogger<AccountRepo>.Instance,
            CreateUserSecretHasher());

        TwoFactorDetailsLookupResult result = TwoFactorDetailsLookupResult.NotConfigured();
        Exception? exception = await Record.ExceptionAsync(async () =>
        {
            result = await repo.GetTwoFactorDetails(Guid.NewGuid(), cancellationToken: CancellationToken.None);
        });

        exception.ShouldBeOfType<DependencyUnavailableException>();
    }

    [Fact]
    public async Task Session_repo_throws_typed_dependency_failure_when_connection_open_fails()
    {
        using var storage = new ThrowingStorageContext();
        var repo = new SessionRepo(
            storage,
            Options.Create(new JWTSettings()),
            NullLogger<SessionRepo>.Instance);

        bool? result = true;
        Exception? exception = await Record.ExceptionAsync(async () =>
        {
            result = await repo.ExpireSession("old-access-token-hash", SystemClock.Instance.GetCurrentInstant(), cancellationToken: CancellationToken.None);
        });

        exception.ShouldBeOfType<DependencyUnavailableException>();
    }

    [Fact]
    public async Task Account_recovery_repo_throws_typed_dependency_failure_when_connection_open_fails()
    {
        using var storage = new ThrowingStorageContext();
        var repo = new AccountRecoveryRepo(
            storage,
            NullLogger<AccountRecoveryRepo>.Instance);

        AccountRecovery_Status? result = AccountRecovery_Status.STARTED;
        Exception? exception = await Record.ExceptionAsync(async () =>
        {
            result = await repo.VerifyUnlock("recovery-token", cancellationToken: CancellationToken.None);
        });

        exception.ShouldBeOfType<DependencyUnavailableException>();
    }

    [Fact]
    public async Task Activation_repo_throws_typed_dependency_failure_when_connection_open_fails()
    {
        using var storage = new ThrowingStorageContext();
        var repo = new ActivationRepo(
            storage,
            NullLogger<ActivationRepo>.Instance);

        treehammock.DataLayer.ActivationCommandResult? result = new treehammock.DataLayer.ActivationCommandResult(true, "unexpected", ActivationStatus.REQUEST);
        Exception? exception = await Record.ExceptionAsync(async () =>
        {
            result = await repo.DisableActivation(
                Guid.NewGuid(),
                Guid.NewGuid(),
                "reader@example.com",
                SystemClock.Instance.GetCurrentInstant(),
                SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromDays(1)),
                ActivationStatus.DISRUPTED, cancellationToken: CancellationToken.None);
        });

        exception.ShouldBeOfType<DependencyUnavailableException>();
    }


    [Theory]
    [InlineData("reader@example.com", "email", 18)]
    [InlineData("+15555550123", "phone", 12)]
    [InlineData("reader", "username", 6)]
    [InlineData("", "blank", 0)]
    public void Repository_identifier_log_scope_carries_metadata_without_identifier_value(
        string identifier,
        string expectedKind,
        int expectedLength)
    {
        RepositorySensitiveValueLogScope scope = RepositoryLogScopes.Identifier(identifier);

        scope.ValueKind.ShouldBe(expectedKind);
        scope.ValueLength.ShouldBe(expectedLength);
        scope.ValueFingerprint.ShouldNotBeNullOrWhiteSpace();

        if (!string.IsNullOrEmpty(identifier))
        {
            scope.ToString().ShouldNotContain(identifier);
        }
    }

    [Fact]
    public void Repository_failure_scopes_do_not_capture_raw_user_identifiers()
    {
        string reposRoot = ProjectFile("Repos");
        string[] repositoryFiles =
        {
            Path.Combine(reposRoot, "AccountRepo.cs"),
            Path.Combine(reposRoot, "AccountRecoveryRepo.cs"),
            Path.Combine(reposRoot, "ActivationRepo.cs"),
            Path.Combine(reposRoot, "SessionRepo.cs")
        };

        string[] forbiddenRawScopeFragments =
        {
            "new { step, single.accountId, single.emailAddress, single.username",
            "new { identifier,",
            "new { emailAddress",
            "new { accountId, emailAddress",
            "new { accountId, username",
            "new { accountId, newEmailAddress",
            "new { tokenHash",
            "new { accessTokenHash",
            "new { accountId, accessTokenHash",
            "new { accountId, expectedOldAccessTokenHash",
            "new { accountId, newAccessTokenHash"
        };

        foreach (string repositoryFile in repositoryFiles)
        {
            string text = File.ReadAllText(repositoryFile);

            foreach (string fragment in forbiddenRawScopeFragments)
            {
                text.Contains(fragment, StringComparison.Ordinal).ShouldBeFalse($"{Path.GetFileName(repositoryFile)} should use RepositoryLogScopes metadata instead of raw failure scope values.");
            }
        }
    }

    private sealed class ThrowingStorageContext : StorageContext
    {
        public ThrowingStorageContext()
            : base(Options.Create(new DatabaseSettings
            {
                servers = "localhost",
                database = "treehammock_tests",
                userId = "treehammock",
                password = "test-password",
                lc_collation = "en_US.UTF-8"
            }))
        {
        }

        public override Task<NpgsqlConnection> CreateConnection(CancellationToken cancellationToken = default)
        {
            throw new InvalidOperationException("Simulated connection-open failure.");
        }
    }


    private static string ProjectRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);

        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "treehammock.sln")))
        {
            directory = directory.Parent;
        }

        directory.ShouldNotBeNull("The test could not locate the project root containing treehammock.sln.");
        return directory.FullName;
    }

    private static string ProjectFile(params string[] relativePathParts)
    {
        return Path.Combine(new[] { ProjectRoot() }.Concat(relativePathParts).ToArray());
    }

    private static IUserSecretHasher CreateUserSecretHasher()
    {
        return new Argon2idUserSecretHasher(Options.Create(new LoginSettings
        {
            PasswordRetryLimit = 3,
            TwoAuthRetryLimit = 3,
            Argon2Iterations = 3,
            Argon2MemoryBytes = 67108864,
            TwoFactorChallengePepper = "0123456789abcdef"
        }));
    }

}
