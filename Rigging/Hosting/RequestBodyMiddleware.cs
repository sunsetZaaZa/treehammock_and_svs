using Microsoft.AspNetCore.Http.Features;
using treehammock.Models.Api;

namespace treehammock.Rigging.Hosting;

// Validate the entire bounded body before security-operation admission or MVC.
// Classification is scoped to our limits/header policy and the codec invocation.
public sealed class RequestBodyMiddleware(RequestDelegate next, RequestBodyPolicy policy)
{
    public const string EncodedTooLarge = "REQUEST_ENCODED_BODY_TOO_LARGE";
    public const string DecodedTooLarge = "REQUEST_DECODED_BODY_TOO_LARGE";
    public const string UnsupportedEncoding = "REQUEST_CONTENT_ENCODING_UNSUPPORTED";
    public const string MultipleEncodings = "REQUEST_CONTENT_ENCODING_MULTIPLE";
    public const string InvalidCompression = "REQUEST_COMPRESSED_BODY_INVALID";
    public const string BodyTimeout = "REQUEST_BODY_TIMEOUT";
    public const string CapacityExceeded = "REQUEST_BODY_CAPACITY_EXCEEDED";
    public async Task InvokeAsync(HttpContext http)
    {
        Stream originalBody = http.Request.Body;
        var originalEncoding = http.Request.Headers.ContentEncoding;
        long? originalLength = http.Request.ContentLength;
        bool entered = false;
        MemoryStream? validatedBody = null;
        try
        {
            http.RequestAborted.ThrowIfCancellationRequested();
            string? encoding = Encoding(http);
            var limits = policy.Limits;
            if (originalLength > limits.EncodedBytes) throw new RequestBodyFailure(413, EncodedTooLarge);
            // Kestrel must allow the single over-limit probe byte so this boundary owns the envelope.
            var transport = http.Features.Get<IHttpMaxRequestBodySizeFeature>();
            if (transport is { IsReadOnly: false } && (transport.MaxRequestBodySize is null || transport.MaxRequestBodySize > limits.EncodedBytes + 1L))
                transport.MaxRequestBodySize = limits.EncodedBytes + 1L;
            bool empty = originalLength == 0 || http.Features.Get<IHttpRequestBodyDetectionFeature>()?.CanHaveBody == false;
            if (empty && encoding is null) { await next(http); http.RequestAborted.ThrowIfCancellationRequested(); return; }
            if (!policy.TryEnter()) throw new RequestBodyFailure(503, CapacityExceeded);
            entered = true;
            int decodedLength;
            byte[] decoded;
            using (var deadline = CancellationTokenSource.CreateLinkedTokenSource(http.RequestAborted))
            {
                deadline.CancelAfter(limits.ReadMilliseconds);
                try
                {
                    var encoded = new byte[limits.EncodedBytes + 1];
                    int length = 0;
                    while (true)
                    {
                        int read = await originalBody.ReadAsync(encoded.AsMemory(length, Math.Min(16 * 1024, encoded.Length - length)), deadline.Token);
                        length += read;
                        if (length == encoded.Length) throw new RequestBodyFailure(413, EncodedTooLarge);
                        if (read == 0) break;
                    }
                    if (encoding is null)
                    {
                        if (length > limits.DecodedBytes) throw new RequestBodyFailure(413, DecodedTooLarge);
                        decoded = encoded; decodedLength = length;
                    }
                    else
                    {
                        decoded = new byte[limits.DecodedBytes + 1];
                        try { decodedLength = await StrictRequestBodyDecoder.DecodeAsync(encoding, encoded, length, decoded, deadline.Token); }
                        catch (InvalidDataException) { throw new RequestBodyFailure(400, InvalidCompression); }
                    }
                    deadline.Token.ThrowIfCancellationRequested();
                }
                catch (OperationCanceledException) when (!http.RequestAborted.IsCancellationRequested && deadline.IsCancellationRequested)
                { throw new RequestBodyFailure(408, BodyTimeout); }
            }
            http.RequestAborted.ThrowIfCancellationRequested();
            validatedBody = new MemoryStream(decoded, 0, decodedLength, writable: false);
            http.Request.Body = validatedBody;
            http.Request.Headers.Remove("Content-Encoding");
            http.Request.ContentLength = decodedLength;
            http.Features.Set(new ValidatedRequestBody(limits.DecodedBytes));
            await next(http);
            http.RequestAborted.ThrowIfCancellationRequested();
        }
        catch (RequestBodyFailure failure) when (!http.Response.HasStarted && !http.RequestAborted.IsCancellationRequested)
        {
            http.Response.Clear(); http.Response.StatusCode = failure.Status;
            SecurityResponseCacheMiddleware.Apply(http.Response);
            if (failure.Status == 503) http.Response.Headers.RetryAfter = "2";
            await http.Response.WriteAsJsonAsync(ApiResponse<object>.Failure(failure.Status, failure.Code), http.RequestAborted);
        }
        finally
        {
            http.Features.Set<ValidatedRequestBody>(null);
            http.Request.Body = originalBody;
            http.Request.ContentLength = originalLength;
            if (originalEncoding.Count == 0) http.Request.Headers.Remove("Content-Encoding");
            else http.Request.Headers.ContentEncoding = originalEncoding;
            validatedBody?.Dispose();
            if (entered) policy.Exit();
        }
    }
    private static string? Encoding(HttpContext http)
    {
        var values = http.Request.Headers.ContentEncoding;
        if (values.Count == 0) return null;
        if (values.Count != 1 || values[0]!.Contains(',')) throw new RequestBodyFailure(415, MultipleEncodings);
        string encoding = values[0]!.Trim().ToLowerInvariant();
        if (encoding is not ("gzip" or "deflate" or "br")) throw new RequestBodyFailure(415, UnsupportedEncoding);
        return encoding;
    }
}
