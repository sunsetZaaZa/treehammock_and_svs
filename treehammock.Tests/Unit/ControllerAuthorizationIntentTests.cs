using System.Reflection;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Routing;
using Shouldly;

using treehammock.Controllers;
using treehammock.Rigging.Authorization.Attributes;

namespace treehammock.Tests.Unit;

public class ControllerAuthorizationIntentTests
{
    private static readonly Type[] ReleaseControllerTypes =
    {
        typeof(AccountRegistrationController),
        typeof(AccountLoginController),
        typeof(AccountTwoFactorController),
        typeof(AccountProfileController),
        typeof(AccountDeleteController),
        typeof(AccountSessionController),
        typeof(AccountRecoveryController),
        typeof(ActivationsController),
        typeof(PasswordResetController),
        typeof(HealthController)
    };

    [Fact]
    public void Every_release_controller_declares_public_or_authenticated_intent_explicitly()
    {
        foreach (Type controllerType in ReleaseControllerTypes)
        {
            bool hasCustomAuthenticate = HasCustomAuthenticate(controllerType);
            bool hasCustomAllowAnonymous = HasCustomAllowAnonymous(controllerType);

            (hasCustomAuthenticate || hasCustomAllowAnonymous)
                .ShouldBeTrue($"{controllerType.Name} must declare its controller-level security intent with the custom authorization attributes.");
            (hasCustomAuthenticate && hasCustomAllowAnonymous)
                .ShouldBeFalse($"{controllerType.Name} must not be both controller-level authenticated and controller-level public.");
        }
    }

    [Theory]
    [InlineData(typeof(AccountRecoveryController))]
    [InlineData(typeof(PasswordResetController))]
    [InlineData(typeof(HealthController))]
    public void Public_controllers_use_custom_allow_anonymous_at_controller_level(Type controllerType)
    {
        HasCustomAllowAnonymous(controllerType).ShouldBeTrue($"{controllerType.Name} must be explicitly public.");
        HasCustomAuthenticate(controllerType).ShouldBeFalse($"{controllerType.Name} must not require an active authenticated session.");
    }

    [Theory]
    [InlineData(typeof(AccountRegistrationController))]
    [InlineData(typeof(AccountLoginController))]
    [InlineData(typeof(AccountTwoFactorController))]
    [InlineData(typeof(AccountProfileController))]
    [InlineData(typeof(AccountDeleteController))]
    [InlineData(typeof(AccountSessionController))]
    [InlineData(typeof(ActivationsController))]
    public void Authenticated_controllers_use_custom_authenticate_at_controller_level(Type controllerType)
    {
        HasCustomAuthenticate(controllerType).ShouldBeTrue($"{controllerType.Name} must be explicitly authenticated.");
        HasCustomAllowAnonymous(controllerType).ShouldBeFalse($"{controllerType.Name} should not be controller-level public.");
    }

    [Theory]
    [InlineData(typeof(AccountRegistrationController), nameof(AccountRegistrationController.AccountSetup))]
    [InlineData(typeof(AccountRegistrationController), nameof(AccountRegistrationController.ResendAccountVerification))]
    [InlineData(typeof(AccountLoginController), nameof(AccountLoginController.Authenticate))]
    [InlineData(typeof(AccountRegistrationController), nameof(AccountRegistrationController.VerifyAccountCreation))]
    [InlineData(typeof(AccountTwoFactorController), nameof(AccountTwoFactorController.TwoFactorAuthenticate))]
    [InlineData(typeof(AccountProfileController), nameof(AccountProfileController.VerifyEmailChange))]
    [InlineData(typeof(AccountDeleteController), nameof(AccountDeleteController.DeleteAccountConfirmation))]
    [InlineData(typeof(AccountDeleteController), nameof(AccountDeleteController.VerifyDeleteAccount))]
    public void Public_account_actions_under_authenticated_controller_use_custom_allow_anonymous(Type controllerType, string actionName)
    {
        MethodInfo method = controllerType.GetMethod(actionName)
            ?? throw new InvalidOperationException($"Missing action {controllerType.Name}.{actionName}.");

        HasCustomAllowAnonymous(method).ShouldBeTrue($"{controllerType.Name}.{actionName} is public by design and must override the account controller custom Authenticate attribute explicitly.");
        HasCustomAuthenticate(method).ShouldBeFalse($"{controllerType.Name}.{actionName} should not carry method-level Authenticate when it is public.");
    }

    [Fact]
    public void No_public_endpoint_relies_on_missing_controller_authorization_metadata()
    {
        foreach ((Type ControllerType, MethodInfo Action) endpoint in ControllerActions())
        {
            bool controllerIsPublic = HasCustomAllowAnonymous(endpoint.ControllerType);
            bool controllerIsAuthenticated = HasCustomAuthenticate(endpoint.ControllerType);
            bool actionIsPublic = HasCustomAllowAnonymous(endpoint.Action);

            if (controllerIsPublic)
            {
                controllerIsAuthenticated.ShouldBeFalse($"{endpoint.ControllerType.Name} must not mix controller-level public and authenticated intent.");
                continue;
            }

            controllerIsAuthenticated.ShouldBeTrue($"{endpoint.ControllerType.Name} must declare custom Authenticate if it is not controller-level public.");

            if (!actionIsPublic)
            {
                endpoint.Action
                    .GetCustomAttributes(typeof(ProducesResponseTypeAttribute), inherit: true)
                    .Cast<ProducesResponseTypeAttribute>()
                    .Select(attribute => attribute.StatusCode)
                    .ShouldContain(StatusCodes.Status401Unauthorized, $"{endpoint.ControllerType.Name}.{endpoint.Action.Name} is authenticated and must advertise 401.");
            }
        }
    }

    [Fact]
    public void Release_controllers_do_not_use_framework_authorization_attributes()
    {
        foreach (Type controllerType in ReleaseControllerTypes)
        {
            controllerType.GetCustomAttributes(typeof(Microsoft.AspNetCore.Authorization.AuthorizeAttribute), inherit: true)
                .ShouldBeEmpty($"{controllerType.Name} must use the project custom Authenticate attribute, not framework Authorize.");
            controllerType.GetCustomAttributes(typeof(Microsoft.AspNetCore.Authorization.AllowAnonymousAttribute), inherit: true)
                .ShouldBeEmpty($"{controllerType.Name} must use the project custom AllowAnonymous attribute, not framework AllowAnonymous.");

            foreach (MethodInfo action in HttpActions(controllerType))
            {
                action.GetCustomAttributes(typeof(Microsoft.AspNetCore.Authorization.AuthorizeAttribute), inherit: true)
                    .ShouldBeEmpty($"{controllerType.Name}.{action.Name} must use custom authorization attributes only.");
                action.GetCustomAttributes(typeof(Microsoft.AspNetCore.Authorization.AllowAnonymousAttribute), inherit: true)
                    .ShouldBeEmpty($"{controllerType.Name}.{action.Name} must use custom authorization attributes only.");
            }
        }
    }

    private static IEnumerable<(Type ControllerType, MethodInfo Action)> ControllerActions()
    {
        foreach (Type controllerType in ReleaseControllerTypes)
        {
            foreach (MethodInfo action in HttpActions(controllerType))
            {
                yield return (controllerType, action);
            }
        }
    }

    private static IEnumerable<MethodInfo> HttpActions(Type controllerType)
    {
        return controllerType
            .GetMethods(BindingFlags.Instance | BindingFlags.Public | BindingFlags.DeclaredOnly)
            .Where(method => method.GetCustomAttributes(inherit: true).OfType<HttpMethodAttribute>().Any());
    }

    private static bool HasCustomAuthenticate(MemberInfo member)
    {
        return member.GetCustomAttributes(typeof(Authenticate), inherit: true).Any();
    }

    private static bool HasCustomAllowAnonymous(MemberInfo member)
    {
        return member.GetCustomAttributes(typeof(AllowAnonymous), inherit: true).Any();
    }
}
