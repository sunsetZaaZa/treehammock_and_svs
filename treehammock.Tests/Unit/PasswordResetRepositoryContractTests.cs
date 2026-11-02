using System.Net;
using System.Reflection;
using NodaTime;
using NpgsqlTypes;
using Shouldly;

using treehammock.Repos;

namespace treehammock.Tests.Unit;

public class PasswordResetRepositoryContractTests
{
    [Fact]
    public void PasswordResetRepo_declares_all_password_reset_sql_function_constants()
    {
        PasswordResetRepo.LookupPasswordResetAccountFunction.ShouldBe("lookup_password_reset_account");
        PasswordResetRepo.CreatePasswordResetRequestFunction.ShouldBe("create_password_reset_request");
        PasswordResetRepo.GetPasswordResetRequestForFinalizeFunction.ShouldBe("get_password_reset_request_for_finalize");
        PasswordResetRepo.RegisterPasswordResetFailedAttemptFunction.ShouldBe("register_password_reset_failed_attempt");
        PasswordResetRepo.PromotePasswordResetFunction.ShouldBe("promote_password_reset");
        PasswordResetRepo.CancelPasswordResetRequestFunction.ShouldBe("cancel_password_reset_request");
        PasswordResetRepo.GetPendingPasswordResetSessionFunction.ShouldBe("get_pending_password_reset_session");
        PasswordResetRepo.TransitionPendingPasswordResetSessionFunction.ShouldBe("transition_pending_password_reset_session");
        PasswordResetRepo.RevokePendingPasswordResetSessionFunction.ShouldBe("revoke_pending_password_reset_session");
        PasswordResetRepo.RegisterPasswordResetRequestRateLimitFunction.ShouldBe("register_password_reset_request_rate_limit");
        PasswordResetRepo.CleanupExpiredPasswordResetRequestsFunction.ShouldBe("cleanup_expired_password_reset_requests");
        PasswordResetRepo.CleanupPasswordResetRateLimitsFunction.ShouldBe("cleanup_password_reset_rate_limits");
    }

    [Fact]
    public void PasswordResetRepo_uses_expected_database_types()
    {
        PasswordResetRepo.InstantDbType.ShouldBe(NpgsqlDbType.TimestampTz);
        PasswordResetRepo.PeriodDbType.ShouldBe(NpgsqlDbType.Interval);
        PasswordResetRepo.PasswordMaterialDbType.ShouldBe(NpgsqlDbType.Bytea);
    }

    [Fact]
    public void PasswordResetRepo_converts_nullable_values_to_DBNull()
    {
        PasswordResetRepo.DbValue(null).ShouldBe(DBNull.Value);
        PasswordResetRepo.DbValue("value").ShouldBe("value");
        PasswordResetRepo.InetDbValue(null).ShouldBe(DBNull.Value);
        PasswordResetRepo.InetDbValue("192.0.2.1").ShouldBe(IPAddress.Parse("192.0.2.1"));
    }

    [Fact]
    public void PasswordResetRepo_finalize_loads_account_binding_from_reset_id_only()
    {
        MethodInfo method = typeof(IPasswordResetRepo).GetMethod(nameof(IPasswordResetRepo.GetPasswordResetRequestForFinalizeAsync))!;
        ParameterInfo[] parameters = method.GetParameters();

        parameters.Any(parameter => parameter.Name == "resetId" && parameter.ParameterType == typeof(Guid)).ShouldBeTrue();
        parameters.Any(parameter => parameter.Name == "accountId").ShouldBeFalse();
    }
    [Fact]
    public void PasswordResetRepo_lookup_result_carries_request_eligibility_metadata()
    {
        PropertyInfo[] properties = typeof(PasswordResetAccountLookupResult).GetProperties();

        properties.Any(property => property.Name == nameof(PasswordResetAccountLookupResult.AccountId) && property.PropertyType == typeof(Guid?)).ShouldBeTrue();
        properties.Any(property => property.Name == nameof(PasswordResetAccountLookupResult.EmailAddress) && property.PropertyType == typeof(string)).ShouldBeTrue();
        properties.Any(property => property.Name == nameof(PasswordResetAccountLookupResult.PhoneNumber) && property.PropertyType == typeof(string)).ShouldBeTrue();
        properties.Any(property => property.Name == nameof(PasswordResetAccountLookupResult.AccountSecurityStamp) && property.PropertyType == typeof(Guid?)).ShouldBeTrue();
        properties.Any(property => property.Name == nameof(PasswordResetAccountLookupResult.EmailVerified) && property.PropertyType == typeof(bool)).ShouldBeTrue();
        properties.Any(property => property.Name == nameof(PasswordResetAccountLookupResult.SmsVerified) && property.PropertyType == typeof(bool)).ShouldBeTrue();
        properties.Any(property => property.Name == nameof(PasswordResetAccountLookupResult.AuthenticatorVerified) && property.PropertyType == typeof(bool)).ShouldBeTrue();
    }

    [Fact]
    public void PasswordResetRepo_cancel_requires_reset_id_timestamp_and_reason()
    {
        MethodInfo method = typeof(IPasswordResetRepo).GetMethod(nameof(IPasswordResetRepo.CancelPasswordResetRequestAsync))!;
        ParameterInfo[] parameters = method.GetParameters();

        parameters.Any(parameter => parameter.Name == "resetId" && parameter.ParameterType == typeof(Guid)).ShouldBeTrue();
        parameters.Any(parameter => parameter.Name == "cancelledAt" && parameter.ParameterType == typeof(Instant)).ShouldBeTrue();
        parameters.Any(parameter => parameter.Name == "reasonCode" && parameter.ParameterType == typeof(string)).ShouldBeTrue();
    }

    [Fact]
    public void PasswordResetRepo_promotion_requires_reset_id_and_loaded_account_id_together()
    {
        PropertyInfo[] commandProperties = typeof(PromotePasswordResetDbCommand).GetProperties();

        commandProperties.Any(property => property.Name == nameof(PromotePasswordResetDbCommand.PasswordResetRequestId) && property.PropertyType == typeof(Guid)).ShouldBeTrue();
        commandProperties.Any(property => property.Name == nameof(PromotePasswordResetDbCommand.AccountId) && property.PropertyType == typeof(Guid)).ShouldBeTrue();
        commandProperties.Any(property => property.Name == nameof(PromotePasswordResetDbCommand.HashedPassword) && property.PropertyType == typeof(byte[])).ShouldBeTrue();
        commandProperties.Any(property => property.Name == nameof(PromotePasswordResetDbCommand.SaltOne) && property.PropertyType == typeof(byte[])).ShouldBeTrue();
        commandProperties.Any(property => property.Name == nameof(PromotePasswordResetDbCommand.Siv) && property.PropertyType == typeof(byte[])).ShouldBeTrue();
        commandProperties.Any(property => property.Name == nameof(PromotePasswordResetDbCommand.Nonce) && property.PropertyType == typeof(byte[])).ShouldBeTrue();
        commandProperties.Any(property => property.Name == nameof(PromotePasswordResetDbCommand.NewSecurityStamp) && property.PropertyType == typeof(Guid)).ShouldBeTrue();
        commandProperties.Any(property => property.Name == nameof(PromotePasswordResetDbCommand.PromotedAt) && property.PropertyType == typeof(Instant)).ShouldBeTrue();
    }

    [Fact]
    public void PasswordResetRepo_create_command_carries_backend_generated_code_and_expiration_metadata()
    {
        PropertyInfo[] commandProperties = typeof(CreatePasswordResetRequestDbCommand).GetProperties();

        commandProperties.Any(property => property.Name == nameof(CreatePasswordResetRequestDbCommand.PasswordResetRequestId) && property.PropertyType == typeof(Guid)).ShouldBeTrue();
        commandProperties.Any(property => property.Name == nameof(CreatePasswordResetRequestDbCommand.AccountId) && property.PropertyType == typeof(Guid)).ShouldBeTrue();
        commandProperties.Any(property => property.Name == nameof(CreatePasswordResetRequestDbCommand.KeyCodeHash) && property.PropertyType == typeof(string)).ShouldBeTrue();
        commandProperties.Any(property => property.Name == nameof(CreatePasswordResetRequestDbCommand.KeyCodeHashVersion) && property.PropertyType == typeof(int?)).ShouldBeTrue();
        commandProperties.Any(property => property.Name == nameof(CreatePasswordResetRequestDbCommand.RequiresKeyCode) && property.PropertyType == typeof(bool)).ShouldBeTrue();
        commandProperties.Any(property => property.Name == nameof(CreatePasswordResetRequestDbCommand.ExpiresAt) && property.PropertyType == typeof(Instant)).ShouldBeTrue();
        commandProperties.Any(property => property.Name == nameof(CreatePasswordResetRequestDbCommand.MaxAttempts) && property.PropertyType == typeof(int)).ShouldBeTrue();
    }

    [Fact]
    public void PasswordResetRepo_result_models_map_sql_lifecycle_codes_without_plaintext_user_proofs()
    {
        string source = File.ReadAllText(ProjectFile("Repos", "PasswordResetRepo.cs"));

        source.ShouldNotContain("public string KeyCode");
        source.ShouldNotContain("public string TotpCode");
        source.ShouldNotContain("public string Password");
        source.ShouldNotContain("VerifyPassword");
    }

    [Fact]
    public void PasswordResetRepo_methods_call_expected_sql_routines_with_named_parameters()
    {
        string source = File.ReadAllText(ProjectFile("Repos", "PasswordResetRepo.cs"));

        source.ShouldContain("LookupPasswordResetAccountFunction");
        source.ShouldContain("CreatePasswordResetRequestFunction");
        source.ShouldContain("GetPasswordResetRequestForFinalizeFunction");
        source.ShouldContain("RegisterPasswordResetFailedAttemptFunction");
        source.ShouldContain("PromotePasswordResetFunction");
        source.ShouldContain("CancelPasswordResetRequestFunction");
        source.ShouldContain("GetPendingPasswordResetSessionFunction");
        source.ShouldContain("TransitionPendingPasswordResetSessionFunction");
        source.ShouldContain("RevokePendingPasswordResetSessionFunction");
        source.ShouldContain("RegisterPasswordResetRequestRateLimitFunction");
        source.ShouldContain("CleanupExpiredPasswordResetRequestsFunction");
        source.ShouldContain("CleanupPasswordResetRateLimitsFunction");

        source.ShouldContain("\"identifier\"");
        source.ShouldContain("\"passwordResetRequestId\"");
        source.ShouldContain("\"accountId\"");
        source.ShouldContain("\"keyCodeHash\"");
        source.ShouldContain("\"expiresAt\"");
        source.ShouldContain("\"maxAttempts\"");
        source.ShouldContain("\"hashedPassword\"");
        source.ShouldContain("\"saltOne\"");
        source.ShouldContain("\"siv\"");
        source.ShouldContain("\"nonce\"");
        source.ShouldContain("\"newSecurityStamp\"");
        source.ShouldContain("\"cancelledAt\"");
        source.ShouldContain("\"reasonCode\"");
        source.ShouldContain("\"resetAccessTokenHash\"");
        source.ShouldContain("\"availableConfigurations\"");
        source.ShouldContain("\"currentExpectedMethod\"");
    }

    [Fact]
    public void PasswordResetRepo_is_registered_as_the_password_reset_repository()
    {
        string source = File.ReadAllText(ProjectFile("Rigging", "DependencyInjection", "TreehammockServiceCollectionExtensions.cs"));

        source.ShouldContain("services.AddSingleton<IPasswordResetRepo, PasswordResetRepo>();");
    }


    [Fact]
    public void PasswordResetRepo_lookup_failure_logging_does_not_include_raw_identifier()
    {
        string source = File.ReadAllText(ProjectFile("Repos", "PasswordResetRepo.cs"));

        source.ShouldNotContain("new { identifier }");
        source.ShouldContain("PasswordResetIdentifierLogScope.From(identifier)");
        source.ShouldContain("IdentifierKind");
        source.ShouldContain("IdentifierLength");
    }

    [Theory]
    [InlineData("reader@example.com", "email", 18)]
    [InlineData("+15555550123", "phone", 12)]
    [InlineData("reader", "username", 6)]
    [InlineData("", "blank", 0)]
    public void PasswordReset_identifier_log_scope_carries_metadata_without_identifier_value(
        string identifier,
        string expectedKind,
        int expectedLength)
    {
        PasswordResetIdentifierLogScope scope = PasswordResetIdentifierLogScope.From(identifier);

        scope.IdentifierKind.ShouldBe(expectedKind);
        scope.IdentifierLength.ShouldBe(expectedLength);

        if (!string.IsNullOrEmpty(identifier))
        {
            scope.ToString().ShouldNotContain(identifier);
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
}
