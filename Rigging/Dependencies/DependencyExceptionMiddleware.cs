using treehammock.Rigging.Authorization;
namespace treehammock.Rigging.Dependencies;

public sealed class DependencyExceptionMiddleware(RequestDelegate next, ILogger<DependencyExceptionMiddleware> logger)
{
    public async Task InvokeAsync(HttpContext context)
    {
        try { await next(context); }
        catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested) { throw; }
        catch (treehammock.Rigging.Security.PasswordWorkBusyException) when (!context.Response.HasStarted)
        {
            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            context.Response.Headers.RetryAfter = "1";
            context.Response.Headers.CacheControl = "no-store";
            await context.Response.WriteAsJsonAsync(treehammock.Models.Api.ApiResponse<object>.Failure(
                StatusCodes.Status503ServiceUnavailable, treehammock.Rigging.Security.PasswordWorkBusyException.Code), context.RequestAborted);
        }
        catch (DependencyUnavailableException ex) when (!context.Response.HasStarted)
        {
            logger.LogWarning("Dependency {Dependency} unavailable during {Operation}; kind {Kind}, stage {Stage}.",
                ex.Failure.Dependency, ex.Failure.Operation, ex.Failure.Kind, ex.Failure.Stage);
            context.Items[AuthContextItems.ActiveSession] = null;
            context.Items[AuthContextItems.WebKey] = null;
            context.Items[AuthContextItems.HashedAccessToken] = null;
            if (ex.Failure.Kind == DependencyFailureKind.CommitOutcomeUnknown &&
                treehammock.Rigging.Operations.SecurityOperationRequestContext.Current is { Admitted: true, OperationId: Guid operationId })
                throw treehammock.DataLayer.Operations.SecurityOperationException.Outcome(new(operationId,
                    treehammock.DataLayer.Operations.SecurityOperationState.Unknown, null, []));
            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            await context.Response.WriteAsJsonAsync(treehammock.Models.Api.ApiResponse<object>.Failure(
                StatusCodes.Status503ServiceUnavailable, "DEPENDENCY_UNAVAILABLE"), context.RequestAborted);
        }
    }
}
