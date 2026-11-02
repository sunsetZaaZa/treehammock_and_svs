namespace treehammock.Rigging.Hosting;

// The API is private by default, including anonymous proof pages and error paths.
// Public caching requires a separately reviewed explicit opt-in; there are no current exceptions.
public sealed class SecurityResponseCacheMiddleware(RequestDelegate next)
{
    public static void Apply(HttpResponse response)
    {
        response.Headers.CacheControl = "no-store";
        response.Headers.Pragma = "no-cache";
        response.Headers.Expires = "Thu, 01 Jan 1970 00:00:00 GMT";
    }

    public async Task InvokeAsync(HttpContext context)
    {
        Apply(context.Response);
        // Registered first: downstream OnStarting callbacks run before this final policy.
        context.Response.OnStarting(static state =>
        {
            Apply((HttpResponse)state);
            return Task.CompletedTask;
        }, context.Response);
        try { await next(context); }
        finally
        {
            if (!context.Response.HasStarted) Apply(context.Response);
        }
    }
}
