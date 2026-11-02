using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Filters;

using treehammock.Rigging.Authorization;
using treehammock.Models.Api;
using treehammock.RiggingSupport.Status;

namespace treehammock.Rigging.Authorization.Attributes;

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public class Authenticate : Attribute, IAuthorizationFilter
{
    public void OnAuthorization(AuthorizationFilterContext context)
    {
        if (HasAllowAnonymous(context))
        {
            return;
        }

        bool authenticated =
            context.HttpContext.Items[AuthContextItems.HashedAccessToken] is string hashedAccessToken &&
            !string.IsNullOrWhiteSpace(hashedAccessToken) &&
            context.HttpContext.Items[AuthContextItems.WebKey] is string webKey &&
            !string.IsNullOrWhiteSpace(webKey);

        if (!authenticated)
        {
            context.Result = ApiResponses.Unauthorized(
                HttpMessage.AUTHENTICATION_FAILED.ToString(),
                new { result = HttpMessage.AUTHENTICATION_FAILED });
        }
    }

    internal static bool HasAllowAnonymous(AuthorizationFilterContext context)
    {
        if (context.ActionDescriptor.EndpointMetadata.OfType<AllowAnonymous>().Any())
        {
            return true;
        }

        if (context.ActionDescriptor is ControllerActionDescriptor controllerActionDescriptor)
        {
            if (controllerActionDescriptor.MethodInfo
                .GetCustomAttributes(typeof(AllowAnonymous), inherit: true)
                .Any())
            {
                return true;
            }

            if (controllerActionDescriptor.ControllerTypeInfo
                .GetCustomAttributes(typeof(AllowAnonymous), inherit: true)
                .Any())
            {
                return true;
            }
        }

        return false;
    }
}
