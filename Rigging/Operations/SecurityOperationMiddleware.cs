using System.Text;
using System.Text.Json;
using treehammock.DataLayer.Operations;
using treehammock.Models.Api;
using treehammock.Services;

namespace treehammock.Rigging.Operations;

public sealed class SecurityOperationMiddleware(RequestDelegate next)
{
    public const string KeyHeader = "Security-Operation-Key";
    public const string RecoveryHeader = "Security-Operation-Recovery-Key";
    public const string StatusPath = "/account/security-operations/status";
    public async Task InvokeAsync(HttpContext http, SecurityOperationService service)
    {
        SecurityOperationRequestContext? context = null;
        bool completed = false;
        try
        {
            if (http.Request.Path.Equals(new PathString(StatusPath)))
            {
                if (!HttpMethods.IsGet(http.Request.Method)) { http.Response.StatusCode = 405; return; }
                string key = OneHeader(http, KeyHeader) ?? throw new SecurityOperationException("SECURITY_OPERATION_KEYS_REQUIRED", 428);
                string recovery = OneHeader(http, RecoveryHeader) ?? throw new SecurityOperationException("SECURITY_OPERATION_KEYS_REQUIRED", 428);
                SecurityOperationStatus status = await service.ReconcileAuthorizedAsync(key, recovery, http.RequestAborted);
                http.Response.StatusCode = status.State switch { SecurityOperationState.Unknown => 503, SecurityOperationState.Pending => 202, SecurityOperationState.Expired => 410, _ => 200 };
                http.Response.Headers.CacheControl = "no-store";
                if (status.State is SecurityOperationState.Pending or SecurityOperationState.Unknown) http.Response.Headers.RetryAfter = "2";
                await http.Response.WriteAsJsonAsync(status, http.RequestAborted);
                return;
            }
            byte[]? canonicalBody=null;
            if (HttpMethods.IsPost(http.Request.Method) && (http.Request.Path.Equals(new PathString("/account/adjust/email/verify")) || http.Request.Path.Equals(new PathString("/account/wipeout/verify"))) && http.Request.HasFormContentType)
            {
                canonicalBody=await CanonicalBodyAsync(http);
                var form=await http.Request.ReadFormAsync(http.RequestAborted);
                http.Request.Body.Position=0;
                if(!http.Request.Headers.ContainsKey(KeyHeader) && form.TryGetValue("operationKey",out var formKey) && formKey.Count==1)
                    http.Request.Headers[KeyHeader]=formKey;
                if(!http.Request.Headers.ContainsKey(RecoveryHeader) && form.TryGetValue("operationRecovery",out var formRecovery) && formRecovery.Count==1)
                    http.Request.Headers[RecoveryHeader]=formRecovery;
            }
            string purpose = http.Request.Method + ":" + http.Request.Path.Value;
            if (purpose.Length > 256) throw new SecurityOperationException("SECURITY_OPERATION_PURPOSE_INVALID", 400);
            context = new()
            {
                ClientKey = OneHeader(http, KeyHeader), RecoveryKey = OneHeader(http, RecoveryHeader),
                Purpose = purpose, CanonicalBody = canonicalBody ?? await CanonicalBodyAsync(http)
            };
            using (SecurityOperationRequestContext.Push(context))
            {
                await next(http);
                completed = true;
                await service.FinishAsync(context, http.Response.StatusCode, http.Response.StatusCode >= 500 || http.RequestAborted.IsCancellationRequested);
            }
        }
        catch (SecurityOperationException ex)
        {
            SecurityOperationStatus? status = ex.Status;
            if (context?.Admitted == true && context.OperationId is Guid id)
            {
                await service.FinishAsync(context, ex.HttpStatus, true);
                status = await service.ReconcileAsync(id);
            }
            if (http.RequestAborted.IsCancellationRequested) throw new OperationCanceledException(http.RequestAborted);
            if (http.Response.HasStarted) throw;
            http.Response.Headers.CacheControl = "no-store";
            if (status?.State is SecurityOperationState.Pending or SecurityOperationState.Unknown) http.Response.Headers.RetryAfter = "2";
            http.Response.StatusCode = status is null ? ex.HttpStatus : SecurityOperationException.Outcome(status).HttpStatus;
            string code = status is null ? ex.Code : SecurityOperationException.Outcome(status).Code;
            await http.Response.WriteAsJsonAsync(ApiResponse<SecurityOperationStatus>.Failure(http.Response.StatusCode, code, status), http.RequestAborted);
        }
        finally
        {
            if (!completed && context?.Admitted == true) await service.FinishAsync(context, 503, true);
            if (context?.RecoveryBytes is byte[] recovery) System.Security.Cryptography.CryptographicOperations.ZeroMemory(recovery);
        }
    }
    private static string? OneHeader(HttpContext http, string name)
    {
        var values = http.Request.Headers[name];
        if (values.Count > 1) throw new SecurityOperationException("SECURITY_OPERATION_HEADER_INVALID", 400);
        return values.Count == 1 && !string.IsNullOrWhiteSpace(values[0]) ? values[0] : null;
    }
    internal static async Task<byte[]> CanonicalBodyAsync(HttpContext http)
    {
        // The host validates the wire/decoded body before this middleware. Keep a
        // bounded defensive reader for direct callers; do not misclassify I/O failures.
        int limit = http.Features.Get<treehammock.Rigging.Hosting.ValidatedRequestBody>()?.DecodedLimit
            ?? treehammock.Rigging.Config.RequestBodySettings.DefaultDecodedBytes;
        http.Request.EnableBuffering(limit + 1, limit + 1L);
        using var body = new MemoryStream();
        var buffer = new byte[16 * 1024];
        try
        {
            int count;
            while ((count = await http.Request.Body.ReadAsync(buffer.AsMemory(0, (int)Math.Min(buffer.Length, limit + 1L - body.Length)), http.RequestAborted)) > 0)
            {
                if (body.Length + count > limit) throw new SecurityOperationException("SECURITY_OPERATION_BODY_TOO_LARGE", 413);
                body.Write(buffer, 0, count);
            }
        }
        finally { http.Request.Body.Position = 0; }
        byte[] bytes = body.ToArray();
        if (bytes.Length > 0 && http.Request.ContentType?.StartsWith("application/json", StringComparison.OrdinalIgnoreCase) == true)
        {
            try
            {
                using var document = JsonDocument.Parse(bytes);
                using var normalized = new MemoryStream();
                using (var writer = new Utf8JsonWriter(normalized)) WriteCanonical(writer, document.RootElement);
                bytes = normalized.ToArray();
            }
            catch (JsonException) { /* MVC retains ownership of malformed-body validation. */ }
        }
        using var result = new MemoryStream(); using var framing = new BinaryWriter(result, Encoding.UTF8, true);
        framing.Write(http.Request.ContentType?.Trim().ToLowerInvariant() ?? "");
        framing.Write(http.Request.QueryString.Value ?? ""); framing.Write(bytes.Length); framing.Write(bytes); framing.Flush();
        return result.ToArray();
    }
    private static void WriteCanonical(Utf8JsonWriter writer, JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            writer.WriteStartObject();
            foreach (var property in value.EnumerateObject().OrderBy(p => p.Name, StringComparer.Ordinal))
            { writer.WritePropertyName(property.Name); WriteCanonical(writer, property.Value); }
            writer.WriteEndObject();
        }
        else if (value.ValueKind == JsonValueKind.Array)
        { writer.WriteStartArray(); foreach (var item in value.EnumerateArray()) WriteCanonical(writer, item); writer.WriteEndArray(); }
        else value.WriteTo(writer);
    }
}
