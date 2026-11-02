using treehammock.Models.Api;

namespace treehammock.Rigging.Hosting;

// Sanitized fallback for unsent HTTP failures; precise body errors belong to RequestBodyMiddleware.
public sealed class HttpExceptionFallbackMiddleware(RequestDelegate next, ILogger<HttpExceptionFallbackMiddleware> logger)
{
    public const string UnexpectedErrorCode = "INTERNAL_SERVER_ERROR";
    public const string RequestErrorCode = "HTTP_REQUEST_FAILED";
    public async Task InvokeAsync(HttpContext context)
    {
        try { await next(context); }
        catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested) { throw; }
        catch (Exception error) when (!context.Response.HasStarted)
        {
            // Preserve an existing HTTP status without inventing compression-specific classification.
            int status = error is BadHttpRequestException request ? request.StatusCode : StatusCodes.Status500InternalServerError;
            string code = error is BadHttpRequestException ? RequestErrorCode : UnexpectedErrorCode;
            // Never pass the exception/message, request path, body, query or credentials to logging.
            logger.LogError("HTTP request failed before response start. Exception type {ExceptionType}.", error.GetType().Name);
            context.Response.Clear();
            context.Response.StatusCode = status;
            SecurityResponseCacheMiddleware.Apply(context.Response);
            await context.Response.WriteAsJsonAsync(ApiResponse<object>.Failure(status, code), context.RequestAborted);
        }
        // A started response keeps its committed no-store header; the server handles abort/cleanup.
    }
}
