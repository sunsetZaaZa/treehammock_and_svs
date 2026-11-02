using Microsoft.AspNetCore.Mvc.Filters;
using treehammock.DataLayer.Cache;
using treehammock.Models.Api;
namespace treehammock.Rigging.Authorization.Attributes;

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public sealed class RequireCapability(string capability) : Attribute, IAuthorizationFilter
{
    public void OnAuthorization(AuthorizationFilterContext context)
    {
        if (Authenticate.HasAllowAnonymous(context)) return;
        if (context.HttpContext.Items[AuthContextItems.ActiveSession] is not ActiveSession session ||
            session.entitlements is null || !session.entitlements.IsCurrent(session.accountId, NodaTime.SystemClock.Instance.GetCurrentInstant()))
        {
            context.Result = ApiResponses.Unauthorized("AUTHENTICATION_FAILED", new { result = "AUTHENTICATION_FAILED" });
            return;
        }
        if (!session.entitlements.Allows(capability))
            context.Result = ApiResponses.JsonFailure(403, "CAPABILITY_DENIED", new { capability });
    }
}
