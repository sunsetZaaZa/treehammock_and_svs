using System.ComponentModel.DataAnnotations;
using Microsoft.Extensions.Options;
using treehammock.Rigging.Config;

namespace treehammock.Rigging.Hosting;

// Immutable host-wide contract, also exposed as controller endpoint metadata.
public sealed record RequestBodyPolicyMetadata(int EncodedBytes, int DecodedBytes, int ConcurrentRequests, int ReadMilliseconds);

public sealed class RequestBodyPolicy : IDisposable
{
    public RequestBodyPolicyMetadata Limits { get; }
    private readonly SemaphoreSlim _capacity;
    public RequestBodyPolicy(IOptions<RequestBodySettings> options)
    {
        var settings = options.Value;
        Validator.ValidateObject(settings, new ValidationContext(settings), validateAllProperties: true);
        Limits = new(settings.EncodedBytes, settings.DecodedBytes, settings.ConcurrentRequests, settings.ReadMilliseconds);
        _capacity = new(Limits.ConcurrentRequests, Limits.ConcurrentRequests);
    }
    internal bool TryEnter() => _capacity.Wait(0);
    internal void Exit() => _capacity.Release();
    public void Dispose() => _capacity.Dispose();
}

// Only installed after the entire wire body has been validated and decoded.
internal sealed record ValidatedRequestBody(int DecodedLimit);
internal sealed class RequestBodyFailure(int status, string code) : Exception(code)
{
    public int Status { get; } = status;
    public string Code { get; } = code;
}
