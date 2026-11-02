using System.Reflection;
using Microsoft.AspNetCore.Mvc;
using Shouldly;

using treehammock.Controllers;
using treehammock.Models.PasswordReset;

namespace treehammock.Tests.Unit;

public sealed class GreenfieldApiNegativeContractTests
{
    [Fact]
    public void Login_twofactor_legacy_method_endpoint_is_absent_from_controller_route_metadata()
    {
        string[] accountPostRoutes =
        [
            .. AccountControllerTypes()
                .SelectMany(type => type.GetMethods(BindingFlags.Instance | BindingFlags.Public | BindingFlags.DeclaredOnly))
                .SelectMany(method => method.GetCustomAttributes<HttpPostAttribute>(inherit: true))
                .Select(attribute => $"/account/{attribute.Template}".Replace("//", "/"))
        ];

        accountPostRoutes.ShouldNotContain("/account/twofactormethod");
        accountPostRoutes.ShouldContain("/account/twofactor/select");
    }
    [Fact]
    public void Password_reset_request_model_exposes_delivery_channel_not_legacy_method()
    {
        string[] propertyNames = typeof(RequestPasswordResetRequest)
            .GetProperties(BindingFlags.Instance | BindingFlags.Public)
            .Select(property => property.Name)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();

        propertyNames.ShouldBe(new[] { "deliveryChannel", "identifier" });
        propertyNames.ShouldNotContain("method");
    }

    [Theory]
    [InlineData("email", true)]
    [InlineData("sms", true)]
    [InlineData("authenticator", false)]
    [InlineData("AUTHENTICATOR_APP", false)]
    [InlineData("email_code_totp", false)]
    [InlineData("sms_code_totp", false)]
    public void Password_reset_public_delivery_channels_are_greenfield_only(string deliveryChannel, bool expected)
    {
        PasswordResetDeliveryChannels.IsSupported(deliveryChannel).ShouldBe(expected);
    }

    private static Type[] AccountControllerTypes()
    {
        return
        [
            typeof(AccountRegistrationController),
            typeof(AccountLoginController),
            typeof(AccountTwoFactorController),
            typeof(AccountProfileController),
            typeof(AccountDeleteController),
            typeof(AccountSessionController),
        ];
    }

    private static string ProjectFile(params string[] parts)
    {
        return Path.Combine(ProjectRoot(), Path.Combine(parts));
    }

    private static string ProjectRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory != null && !File.Exists(Path.Combine(directory.FullName, "treehammock.csproj")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new InvalidOperationException("Project root could not be found.");
    }
}
