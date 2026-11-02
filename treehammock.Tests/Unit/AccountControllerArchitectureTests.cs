using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Routing;
using Shouldly;

using treehammock.Controllers;

namespace treehammock.Tests.Unit;

public class AccountControllerArchitectureTests
{
    [Fact]
    public void Account_surface_is_split_into_named_bounded_controller_source_files()
    {
        string controllersRoot = ProjectFile("Controllers");
        string[] boundedFiles = Directory.GetFiles(controllersRoot, "Account*Controller*.cs")
            .Select(Path.GetFileName)
            .OrderBy(name => name)
            .ToArray()!;

        boundedFiles.ShouldContain("AccountRegistrationController.cs");
        boundedFiles.ShouldContain("AccountLoginController.cs");
        boundedFiles.ShouldContain("AccountTwoFactorController.cs");
        boundedFiles.ShouldContain("AccountProfileController.cs");
        boundedFiles.ShouldContain("AccountDeleteController.cs");
        boundedFiles.ShouldContain("AccountSessionController.cs");
        boundedFiles.ShouldContain("AccountControllerBase.cs");

        Directory.GetFiles(controllersRoot, "AccountController.*.cs")
            .ShouldBeEmpty("old bounded partial action files should not remain after the named controller split.");
        File.Exists(Path.Combine(controllersRoot, "AccountController.cs"))
            .ShouldBeFalse("the old aggregate AccountController source should be replaced by AccountControllerBase plus named bounded controllers.");
    }

    [Fact]
    public void Account_controller_base_is_abstract_shared_base_and_has_no_http_actions()
    {
        string source = File.ReadAllText(ProjectFile("Controllers", "AccountControllerBase.cs"));

        source.ShouldContain("public abstract partial class AccountControllerBase : ControllerBase");
        source.ShouldContain("protected AccountControllerBase(");
        source.ShouldNotContain("[NonController]");
        source.ShouldNotContain("[HttpPost(");
        source.ShouldNotContain("[HttpGet(");

        typeof(AccountControllerBase).IsAbstract.ShouldBeTrue();
        typeof(AccountControllerBase)
            .GetCustomAttributes(typeof(NonControllerAttribute), inherit: true)
            .ShouldBeEmpty("[NonController] is inherited by named derived controllers and prevents MVC endpoint discovery.");
    }

    [Theory]
    [InlineData(typeof(AccountRegistrationController), "AccountRegistrationController.cs")]
    [InlineData(typeof(AccountLoginController), "AccountLoginController.cs")]
    [InlineData(typeof(AccountTwoFactorController), "AccountTwoFactorController.cs")]
    [InlineData(typeof(AccountProfileController), "AccountProfileController.cs")]
    [InlineData(typeof(AccountDeleteController), "AccountDeleteController.cs")]
    [InlineData(typeof(AccountSessionController), "AccountSessionController.cs")]
    public void Named_account_controllers_own_mvc_metadata_and_account_route(Type controllerType, string fileName)
    {
        string source = File.ReadAllText(ProjectFile("Controllers", fileName));

        source.ShouldContain("[Authenticate]");
        source.ShouldContain("[ApiController]");
        source.ShouldContain("[Route(\"account\")]");
        source.ShouldContain($"public sealed class {controllerType.Name} : AccountControllerBase");
        source.ShouldContain($"public {controllerType.Name}(");

        controllerType.GetCustomAttributes(typeof(ApiControllerAttribute), inherit: true)
            .ShouldNotBeEmpty();
        controllerType.GetCustomAttributes(typeof(RouteAttribute), inherit: true)
            .Cast<RouteAttribute>()
            .Select(attribute => attribute.Template)
            .ShouldContain("account");
    }

    [Fact]
    public void Account_endpoint_actions_live_on_their_named_bounded_controllers()
    {
        var actionOwners = new Dictionary<Type, string[]>
        {
            [typeof(AccountRegistrationController)] =
            [
                nameof(AccountRegistrationController.AccountSetup),
                nameof(AccountRegistrationController.ResendAccountVerification),
                nameof(AccountRegistrationController.VerifyAccountCreation),
            ],
            [typeof(AccountLoginController)] =
            [
                nameof(AccountLoginController.Authenticate),
            ],
            [typeof(AccountTwoFactorController)] =
            [
                nameof(AccountTwoFactorController.StartAuthenticatorAppSetup),
                nameof(AccountTwoFactorController.VerifyAuthenticatorAppSetup),
                nameof(AccountTwoFactorController.CancelAuthenticatorAppSetup),
                nameof(AccountTwoFactorController.SetupTwoFactorMethod),
                nameof(AccountTwoFactorController.VerifyTwoFactorMethod),
                nameof(AccountTwoFactorController.SelectTwoFactorConfiguration),
                nameof(AccountTwoFactorController.TwoFactorAuthenticate),
            ],
            [typeof(AccountProfileController)] =
            [
                nameof(AccountProfileController.ModifyAccount),
                nameof(AccountProfileController.VerifyEmailChange),
                nameof(AccountProfileController.ConfirmEmailChange),
                nameof(AccountProfileController.ViewAccount),
            ],
            [typeof(AccountDeleteController)] =
            [
                nameof(AccountDeleteController.DeleteAccount),
                nameof(AccountDeleteController.DeleteAccountConfirmation),
                nameof(AccountDeleteController.VerifyDeleteAccount),
                nameof(AccountDeleteController.FinalizeDeleteAccount),
            ],
            [typeof(AccountSessionController)] =
            [
                nameof(AccountSessionController.Reauthenticate),
                nameof(AccountSessionController.LogoffAccount),
                nameof(AccountSessionController.LogoffAllAccount),
                nameof(AccountSessionController.ListActiveSessions),
                nameof(AccountSessionController.RevokeSession),
            ],
        };

        foreach ((Type controllerType, string[] actionNames) in actionOwners)
        {
            foreach (string actionName in actionNames)
            {
                var action = controllerType.GetMethod(actionName);
                action.ShouldNotBeNull($"{actionName} should live on {controllerType.Name}.");
                action!
                    .GetCustomAttributes(inherit: true)
                    .OfType<HttpMethodAttribute>()
                    .ShouldNotBeEmpty($"{controllerType.Name}.{actionName} should remain an HTTP endpoint action.");
            }
        }
    }

    [Fact]
    public void Bounded_account_controller_source_files_stay_under_size_limit()
    {
        string controllersRoot = ProjectFile("Controllers");
        foreach (string file in Directory.GetFiles(controllersRoot, "Account*Controller*.cs"))
        {
            int lineCount = File.ReadLines(file).Count();
            lineCount.ShouldBeLessThanOrEqualTo(1600, $"{Path.GetFileName(file)} should stay bounded after named controller split.");
        }
    }

    private static string ProjectRoot()
    {
        string current = AppContext.BaseDirectory;
        DirectoryInfo? directory = new(current);

        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "treehammock.csproj")))
        {
            directory = directory.Parent;
        }

        if (directory is null)
        {
            throw new DirectoryNotFoundException("Could not locate treehammock project root.");
        }

        return directory.FullName;
    }

    private static string ProjectFile(params string[] parts)
    {
        return Path.Combine([ProjectRoot(), .. parts]);
    }
}
