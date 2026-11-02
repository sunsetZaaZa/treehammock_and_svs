using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Shouldly;

using treehammock.Controllers;
using treehammock.Rigging.Authorization.Attributes;

namespace treehammock.Tests.Unit;

public class AccountControllerAuthorizationMetadataTests
{
    private static readonly Type[] AccountControllerTypes =
    [
        typeof(AccountRegistrationController),
        typeof(AccountLoginController),
        typeof(AccountTwoFactorController),
        typeof(AccountProfileController),
        typeof(AccountDeleteController),
        typeof(AccountSessionController),
    ];

    [Fact]
    public void Named_account_controllers_use_custom_authenticate_attribute()
    {
        foreach (Type controllerType in AccountControllerTypes)
        {
            controllerType
                .GetCustomAttributes(typeof(Authenticate), inherit: true)
                .ShouldNotBeEmpty($"{controllerType.Name} must keep the custom authenticated account boundary.");
        }
    }

    [Fact]
    public void Account_controller_base_is_abstract_and_does_not_mark_derived_controllers_non_controller()
    {
        typeof(AccountControllerBase).IsAbstract.ShouldBeTrue();
        typeof(AccountControllerBase)
            .GetCustomAttributes(typeof(NonControllerAttribute), inherit: true)
            .ShouldBeEmpty("[NonController] is inherited by named derived controllers and prevents MVC endpoint discovery.");
    }

    [Theory]
    [InlineData(typeof(AccountRegistrationController), nameof(AccountRegistrationController.AccountSetup))]
    [InlineData(typeof(AccountRegistrationController), nameof(AccountRegistrationController.ResendAccountVerification))]
    [InlineData(typeof(AccountRegistrationController), nameof(AccountRegistrationController.VerifyAccountCreation))]
    [InlineData(typeof(AccountLoginController), nameof(AccountLoginController.Authenticate))]
    [InlineData(typeof(AccountTwoFactorController), nameof(AccountTwoFactorController.SelectTwoFactorConfiguration))]
    [InlineData(typeof(AccountTwoFactorController), nameof(AccountTwoFactorController.TwoFactorAuthenticate))]
    [InlineData(typeof(AccountProfileController), nameof(AccountProfileController.ConfirmEmailChange))]
    [InlineData(typeof(AccountDeleteController), nameof(AccountDeleteController.DeleteAccountConfirmation))]
    [InlineData(typeof(AccountDeleteController), nameof(AccountDeleteController.VerifyDeleteAccount))]
    public void Public_account_endpoints_use_custom_allow_anonymous(Type controllerType, string methodName)
    {
        var method = controllerType.GetMethod(methodName);

        method.ShouldNotBeNull();
        method!
            .GetCustomAttributes(typeof(AllowAnonymous), inherit: true)
            .ShouldNotBeEmpty();
    }

    [Theory]
    [InlineData(typeof(AccountTwoFactorController), nameof(AccountTwoFactorController.StartAuthenticatorAppSetup))]
    [InlineData(typeof(AccountTwoFactorController), nameof(AccountTwoFactorController.VerifyAuthenticatorAppSetup))]
    [InlineData(typeof(AccountTwoFactorController), nameof(AccountTwoFactorController.CancelAuthenticatorAppSetup))]
    [InlineData(typeof(AccountTwoFactorController), nameof(AccountTwoFactorController.RemoveTwoFactorMethod))]
    [InlineData(typeof(AccountTwoFactorController), nameof(AccountTwoFactorController.SetupTwoFactorMethod))]
    [InlineData(typeof(AccountTwoFactorController), nameof(AccountTwoFactorController.VerifyTwoFactorMethod))]
    [InlineData(typeof(AccountProfileController), nameof(AccountProfileController.ModifyAccount))]
    [InlineData(typeof(AccountProfileController), nameof(AccountProfileController.ViewAccount))]
    [InlineData(typeof(AccountDeleteController), nameof(AccountDeleteController.DeleteAccount))]
    [InlineData(typeof(AccountDeleteController), nameof(AccountDeleteController.FinalizeDeleteAccount))]
    [InlineData(typeof(AccountSessionController), nameof(AccountSessionController.Reauthenticate))]
    [InlineData(typeof(AccountSessionController), nameof(AccountSessionController.LogoffAccount))]
    [InlineData(typeof(AccountSessionController), nameof(AccountSessionController.LogoffAllAccount))]
    [InlineData(typeof(AccountSessionController), nameof(AccountSessionController.ListActiveSessions))]
    [InlineData(typeof(AccountSessionController), nameof(AccountSessionController.RevokeSession))]
    public void Protected_endpoints_advertise_custom_authenticate_401_response(Type controllerType, string methodName)
    {
        var method = controllerType.GetMethod(methodName);

        method.ShouldNotBeNull();
        method!
            .GetCustomAttributes(typeof(AllowAnonymous), inherit: true)
            .ShouldBeEmpty($"{controllerType.Name}.{methodName} should remain protected by the controller-level custom Authenticate attribute.");
        MethodStatusCodes(method).ShouldContain(StatusCodes.Status401Unauthorized);
    }

    [Theory]
    [InlineData(typeof(AccountLoginController), nameof(AccountLoginController.Authenticate))]
    [InlineData(typeof(AccountTwoFactorController), nameof(AccountTwoFactorController.VerifyTwoFactorMethod))]
    [InlineData(typeof(AccountProfileController), nameof(AccountProfileController.ConfirmEmailChange))]
    [InlineData(typeof(AccountDeleteController), nameof(AccountDeleteController.VerifyDeleteAccount))]
    [InlineData(typeof(AccountDeleteController), nameof(AccountDeleteController.FinalizeDeleteAccount))]
    public void Counter_store_failure_paths_advertise_503_response(Type controllerType, string methodName)
    {
        var method = controllerType.GetMethod(methodName);

        method.ShouldNotBeNull();
        MethodStatusCodes(method!).ShouldContain(StatusCodes.Status503ServiceUnavailable);
    }

    [Theory]
    [InlineData(typeof(AccountRegistrationController), nameof(AccountRegistrationController.AccountSetup))]
    [InlineData(typeof(AccountRegistrationController), nameof(AccountRegistrationController.ResendAccountVerification))]
    [InlineData(typeof(AccountLoginController), nameof(AccountLoginController.Authenticate))]
    [InlineData(typeof(AccountTwoFactorController), nameof(AccountTwoFactorController.StartAuthenticatorAppSetup))]
    [InlineData(typeof(AccountTwoFactorController), nameof(AccountTwoFactorController.VerifyAuthenticatorAppSetup))]
    [InlineData(typeof(AccountTwoFactorController), nameof(AccountTwoFactorController.CancelAuthenticatorAppSetup))]
    [InlineData(typeof(AccountTwoFactorController), nameof(AccountTwoFactorController.RemoveTwoFactorMethod))]
    [InlineData(typeof(AccountTwoFactorController), nameof(AccountTwoFactorController.SetupTwoFactorMethod))]
    [InlineData(typeof(AccountTwoFactorController), nameof(AccountTwoFactorController.VerifyTwoFactorMethod))]
    [InlineData(typeof(AccountTwoFactorController), nameof(AccountTwoFactorController.SelectTwoFactorConfiguration))]
    [InlineData(typeof(AccountTwoFactorController), nameof(AccountTwoFactorController.TwoFactorAuthenticate))]
    [InlineData(typeof(AccountProfileController), nameof(AccountProfileController.ConfirmEmailChange))]
    [InlineData(typeof(AccountDeleteController), nameof(AccountDeleteController.VerifyDeleteAccount))]
    [InlineData(typeof(AccountProfileController), nameof(AccountProfileController.ModifyAccount))]
    [InlineData(typeof(AccountDeleteController), nameof(AccountDeleteController.DeleteAccount))]
    [InlineData(typeof(AccountDeleteController), nameof(AccountDeleteController.FinalizeDeleteAccount))]
    [InlineData(typeof(AccountSessionController), nameof(AccountSessionController.Reauthenticate))]
    [InlineData(typeof(AccountSessionController), nameof(AccountSessionController.LogoffAccount))]
    [InlineData(typeof(AccountSessionController), nameof(AccountSessionController.LogoffAllAccount))]
    [InlineData(typeof(AccountSessionController), nameof(AccountSessionController.RevokeSession))]
    public void Endpoints_with_validation_paths_advertise_400_response(Type controllerType, string methodName)
    {
        var method = controllerType.GetMethod(methodName);

        method.ShouldNotBeNull();
        MethodStatusCodes(method!).ShouldContain(StatusCodes.Status400BadRequest);
    }
    [Theory]
    [InlineData(typeof(AccountLoginController), nameof(AccountLoginController.Authenticate))]
    [InlineData(typeof(AccountDeleteController), nameof(AccountDeleteController.DeleteAccount))]
    [InlineData(typeof(AccountDeleteController), nameof(AccountDeleteController.FinalizeDeleteAccount))]
    [InlineData(typeof(AccountTwoFactorController), nameof(AccountTwoFactorController.VerifyAuthenticatorAppSetup))]
    [InlineData(typeof(AccountTwoFactorController), nameof(AccountTwoFactorController.VerifyTwoFactorMethod))]
    [InlineData(typeof(AccountProfileController), nameof(AccountProfileController.ConfirmEmailChange))]
    [InlineData(typeof(AccountDeleteController), nameof(AccountDeleteController.VerifyDeleteAccount))]
    public void Endpoints_with_rate_limit_paths_advertise_429_response(Type controllerType, string methodName)
    {
        var method = controllerType.GetMethod(methodName);

        method.ShouldNotBeNull();
        MethodStatusCodes(method!).ShouldContain(StatusCodes.Status429TooManyRequests);
    }

    [Theory]
    [InlineData(typeof(AccountTwoFactorController), nameof(AccountTwoFactorController.StartAuthenticatorAppSetup))]
    [InlineData(typeof(AccountTwoFactorController), nameof(AccountTwoFactorController.VerifyAuthenticatorAppSetup))]
    [InlineData(typeof(AccountTwoFactorController), nameof(AccountTwoFactorController.CancelAuthenticatorAppSetup))]
    [InlineData(typeof(AccountTwoFactorController), nameof(AccountTwoFactorController.RemoveTwoFactorMethod))]
    [InlineData(typeof(AccountTwoFactorController), nameof(AccountTwoFactorController.SetupTwoFactorMethod))]
    [InlineData(typeof(AccountProfileController), nameof(AccountProfileController.ModifyAccount))]
    [InlineData(typeof(AccountDeleteController), nameof(AccountDeleteController.DeleteAccount))]
    [InlineData(typeof(AccountDeleteController), nameof(AccountDeleteController.FinalizeDeleteAccount))]
    [InlineData(typeof(AccountSessionController), nameof(AccountSessionController.LogoffAllAccount))]
    [InlineData(typeof(AccountSessionController), nameof(AccountSessionController.RevokeSession))]
    public void Endpoints_with_required_idempotency_key_advertise_428_response(Type controllerType, string methodName)
    {
        var method = controllerType.GetMethod(methodName);

        method.ShouldNotBeNull();
        MethodStatusCodes(method!).ShouldContain(StatusCodes.Status428PreconditionRequired);
    }

    [Theory]
    [InlineData(typeof(AccountRegistrationController), nameof(AccountRegistrationController.AccountSetup))]
    [InlineData(typeof(AccountLoginController), nameof(AccountLoginController.Authenticate))]
    public void Account_lockout_paths_advertise_423_response(Type controllerType, string methodName)
    {
        var method = controllerType.GetMethod(methodName);

        method.ShouldNotBeNull();
        MethodStatusCodes(method!).ShouldContain(StatusCodes.Status423Locked);
    }

    private static string MatrixRowForRoute(string matrix, string route)
    {
        string routeCell = $"`{route}`";
        string? row = matrix
            .Split(new[] { "\r\n", "\n" }, StringSplitOptions.None)
            .FirstOrDefault(line => line.Contains(routeCell, StringComparison.Ordinal));

        row.ShouldNotBeNull($"The endpoint matrix must include a row for {route}.");
        return row!;
    }

    private static string MatrixAuthColumn(string row)
    {
        string[] columns = row
            .Split('|', StringSplitOptions.TrimEntries)
            .Where(column => column.Length > 0)
            .ToArray();

        columns.Length.ShouldBeGreaterThanOrEqualTo(3, "Endpoint matrix rows must include Method, Route, and Auth columns.");
        return columns[2];
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

    private static IReadOnlySet<int> MethodStatusCodes(System.Reflection.MethodInfo method)
    {
        return method
            .GetCustomAttributes(typeof(ProducesResponseTypeAttribute), inherit: true)
            .Cast<ProducesResponseTypeAttribute>()
            .Select(attribute => attribute.StatusCode)
            .ToHashSet();
    }
}
