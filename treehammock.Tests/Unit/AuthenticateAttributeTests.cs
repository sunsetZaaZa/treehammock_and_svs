using System.Reflection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Routing;
using Shouldly;

using treehammock.Models.Api;
using treehammock.Rigging.Authorization.Attributes;
using treehammock.RiggingSupport.Status;

namespace treehammock.Tests.Unit;

public class AuthenticateAttributeTests
{
    [Fact]
    public void OnAuthorization_without_validated_middleware_context_returns_401_envelope()
    {
        var context = BuildAuthorizationContext();
        var attribute = new Authenticate();

        attribute.OnAuthorization(context);

        var envelope = ExtractUnauthorizedEnvelope(context);
        envelope.success.ShouldBeFalse();
        envelope.statusCode.ShouldBe(StatusCodes.Status401Unauthorized);
        envelope.code.ShouldBe(HttpMessage.AUTHENTICATION_FAILED.ToString());
        ExtractResult(envelope.data).ShouldBe(HttpMessage.AUTHENTICATION_FAILED);
    }

    [Fact]
    public void OnAuthorization_with_fake_raw_header_but_no_validated_context_returns_401_envelope()
    {
        var context = BuildAuthorizationContext();
        context.HttpContext.Request.Headers["AccessToken"] = "potato";
        var attribute = new Authenticate();

        attribute.OnAuthorization(context);

        var envelope = ExtractUnauthorizedEnvelope(context);
        envelope.success.ShouldBeFalse();
        envelope.statusCode.ShouldBe(StatusCodes.Status401Unauthorized);
        envelope.code.ShouldBe(HttpMessage.AUTHENTICATION_FAILED.ToString());
        ExtractResult(envelope.data).ShouldBe(HttpMessage.AUTHENTICATION_FAILED);
    }

    [Fact]
    public void OnAuthorization_with_validated_active_session_context_allows_request()
    {
        var context = BuildAuthorizationContext();
        context.HttpContext.Items["hashedAccessToken"] = "validated-token-hash";
        context.HttpContext.Items["webKey"] = "validated-web-key";
        var attribute = new Authenticate();

        attribute.OnAuthorization(context);

        context.Result.ShouldBeNull();
    }

    [Fact]
    public void OnAuthorization_skips_custom_allow_anonymous_endpoints()
    {
        var context = BuildAuthorizationContext(new AllowAnonymous());
        var attribute = new Authenticate();

        attribute.OnAuthorization(context);

        context.Result.ShouldBeNull();
    }

    [Fact]
    public void OnAuthorization_skips_custom_allow_anonymous_method_metadata()
    {
        var context = BuildAuthorizationContextForMethod(
            typeof(MethodAnonymousController),
            nameof(MethodAnonymousController.OpenAction));
        var attribute = new Authenticate();

        attribute.OnAuthorization(context);

        context.Result.ShouldBeNull();
    }

    [Fact]
    public void OnAuthorization_skips_custom_allow_anonymous_controller_metadata()
    {
        var context = BuildAuthorizationContextForMethod(
            typeof(ControllerAnonymousController),
            nameof(ControllerAnonymousController.OpenAction));
        var attribute = new Authenticate();

        attribute.OnAuthorization(context);

        context.Result.ShouldBeNull();
    }

    [Fact]
    public void OnAuthorization_blocks_controller_action_descriptor_without_allow_anonymous()
    {
        var context = BuildAuthorizationContextForMethod(
            typeof(ProtectedController),
            nameof(ProtectedController.ProtectedAction));
        var attribute = new Authenticate();

        attribute.OnAuthorization(context);

        ExtractUnauthorizedEnvelope(context);
    }

    private static ApiResponse<object> ExtractUnauthorizedEnvelope(AuthorizationFilterContext context)
    {
        JsonResult result = context.Result.ShouldBeOfType<JsonResult>();
        result.StatusCode.ShouldBe(StatusCodes.Status401Unauthorized);

        ApiResponse<object> envelope = result.Value.ShouldBeOfType<ApiResponse<object>>();
        envelope.statusCode.ShouldBe(StatusCodes.Status401Unauthorized);
        return envelope;
    }

    private static HttpMessage ExtractResult(object? data)
    {
        data.ShouldNotBeNull();
        var property = data!.GetType().GetProperty("result");
        property.ShouldNotBeNull();
        return property!.GetValue(data).ShouldBeOfType<HttpMessage>();
    }

    private static AuthorizationFilterContext BuildAuthorizationContext(params object[] endpointMetadata)
    {
        var httpContext = new DefaultHttpContext();
        var actionDescriptor = new ActionDescriptor
        {
            EndpointMetadata = endpointMetadata.ToList()
        };
        var actionContext = new ActionContext(httpContext, new RouteData(), actionDescriptor);
        return new AuthorizationFilterContext(actionContext, new List<IFilterMetadata>());
    }

    private static AuthorizationFilterContext BuildAuthorizationContextForMethod(Type controllerType, string methodName)
    {
        MethodInfo? methodInfo = controllerType.GetMethod(methodName);
        methodInfo.ShouldNotBeNull();

        var httpContext = new DefaultHttpContext();
        var actionDescriptor = new ControllerActionDescriptor
        {
            ControllerTypeInfo = controllerType.GetTypeInfo(),
            MethodInfo = methodInfo!,
            EndpointMetadata = new List<object>()
        };
        var actionContext = new ActionContext(httpContext, new RouteData(), actionDescriptor);
        return new AuthorizationFilterContext(actionContext, new List<IFilterMetadata>());
    }

    private sealed class MethodAnonymousController
    {
        [AllowAnonymous]
        public void OpenAction()
        {
        }
    }

    [AllowAnonymous]
    private sealed class ControllerAnonymousController
    {
        public void OpenAction()
        {
        }
    }

    private sealed class ProtectedController
    {
        public void ProtectedAction()
        {
        }
    }
}
