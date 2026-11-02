using System.Reflection;
using NodaTime;
using NpgsqlTypes;
using Shouldly;

using treehammock.Repos;

namespace treehammock.Tests.Unit;

public class PasswordResetTotpRepositoryContractTests
{
    [Fact]
    public void PasswordResetTotpRepo_declares_sql_function_constants()
    {
        PasswordResetTotpRepo.GetPasswordResetTotpEnrollmentFunction.ShouldBe("get_password_reset_totp_enrollment");
        PasswordResetTotpRepo.MarkPasswordResetTotpStepUsedFunction.ShouldBe("mark_password_reset_totp_step_used");
    }

    [Fact]
    public void PasswordResetTotpRepo_uses_expected_database_types()
    {
        PasswordResetTotpRepo.InstantDbType.ShouldBe(NpgsqlDbType.TimestampTz);
        PasswordResetTotpRepo.ProtectedSecretDbType.ShouldBe(NpgsqlDbType.Bytea);
    }

    [Fact]
    public void PasswordResetTotpRepo_interface_exposes_lookup_and_replay_marking_only()
    {
        MethodInfo lookup = typeof(IPasswordResetTotpRepo).GetMethod(nameof(IPasswordResetTotpRepo.GetPasswordResetTotpEnrollmentAsync))!;
        MethodInfo mark = typeof(IPasswordResetTotpRepo).GetMethod(nameof(IPasswordResetTotpRepo.MarkPasswordResetTotpStepUsedAsync))!;

        lookup.GetParameters().Any(parameter => parameter.Name == "accountId" && parameter.ParameterType == typeof(Guid)).ShouldBeTrue();
        lookup.GetParameters().Any(parameter => parameter.Name == "now" && parameter.ParameterType == typeof(Instant)).ShouldBeTrue();
        mark.GetParameters().Any(parameter => parameter.Name == "twoFactorIndex" && parameter.ParameterType == typeof(long)).ShouldBeTrue();
        mark.GetParameters().Any(parameter => parameter.Name == "timeStep" && parameter.ParameterType == typeof(long)).ShouldBeTrue();
    }

    [Fact]
    public void Enrollment_record_carries_protected_secret_fields_without_plaintext_secret_or_totp_code()
    {
        PropertyInfo[] properties = typeof(PasswordResetTotpEnrollmentRecord).GetProperties();

        properties.Any(property => property.Name == nameof(PasswordResetTotpEnrollmentRecord.AccountId) && property.PropertyType == typeof(Guid)).ShouldBeTrue();
        properties.Any(property => property.Name == nameof(PasswordResetTotpEnrollmentRecord.TwoFactorIndex) && property.PropertyType == typeof(long)).ShouldBeTrue();
        properties.Any(property => property.Name == nameof(PasswordResetTotpEnrollmentRecord.TotpSecretCiphertext) && property.PropertyType == typeof(byte[])).ShouldBeTrue();
        properties.Any(property => property.Name == nameof(PasswordResetTotpEnrollmentRecord.TotpSecretNonce) && property.PropertyType == typeof(byte[])).ShouldBeTrue();
        properties.Any(property => property.Name == nameof(PasswordResetTotpEnrollmentRecord.TotpSecretTag) && property.PropertyType == typeof(byte[])).ShouldBeTrue();
        properties.Any(property => property.Name == nameof(PasswordResetTotpEnrollmentRecord.TotpSecretVersion) && property.PropertyType == typeof(int)).ShouldBeTrue();
        properties.Any(property => property.Name == nameof(PasswordResetTotpEnrollmentRecord.TotpLastUsedStep) && property.PropertyType == typeof(long?)).ShouldBeTrue();
        properties.Any(property => property.Name.Contains("Plaintext", StringComparison.OrdinalIgnoreCase)).ShouldBeFalse();
        properties.Any(property => property.Name.Contains("TotpCode", StringComparison.OrdinalIgnoreCase)).ShouldBeFalse();
    }

    [Fact]
    public void PasswordResetTotpRepo_does_not_log_protected_secret_bytes()
    {
        string source = File.ReadAllText(ProjectFile("Repos", "PasswordResetTotpRepo.cs"));

        source.ShouldContain("get_password_reset_totp_enrollment");
        source.ShouldContain("mark_password_reset_totp_step_used");
        source.ShouldNotContain("TotpSecretCiphertext }");
        source.ShouldNotContain("TotpSecretNonce }");
        source.ShouldNotContain("TotpSecretTag }");
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
