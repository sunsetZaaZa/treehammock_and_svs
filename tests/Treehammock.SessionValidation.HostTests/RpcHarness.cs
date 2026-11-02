using Xunit;
using System.Buffers.Binary;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Google.Protobuf;
using Microsoft.IdentityModel.Tokens;
using NodaTime;
using Treehammock.SessionValidation.Api;
using Treehammock.SessionValidation.Contracts;
using Treehammock.SessionValidation.Contracts.V1;
using Treehammock.SessionValidation.Core;
using Treehammock.SessionValidation.Storage;
namespace Treehammock.SessionValidation.HostTests;

internal sealed class RpcResources : IHostResources, IReadonlySessionAuthority
{
    internal readonly SessionIdentity Identity = new(Guid.NewGuid(), Guid.NewGuid(), 7, 2, Guid.NewGuid(), Guid.NewGuid());
    internal readonly byte[] Key = RandomNumberGenerator.GetBytes(64);
    internal int Calls;
    internal AuthorityReadStatus Status = AuthorityReadStatus.Found;
    internal Func<string, Instant, CancellationToken, Task<AuthorityReadResult>>? Read;
    public bool DatabaseReady => Status != AuthorityReadStatus.Unavailable;
    public DatabaseIdentityAuditStatus LastAudit => DatabaseIdentityAuditStatus.Verified;
    public SessionCacheAdmission Admission { get; } = new();
    public SessionEvidenceCoordinator Coordinator { get; }
    internal RpcResources(IGuardedSessionRefillQueue? refill = null)
    {
        Coordinator = new(new(new NoCache(), Admission, TimeSpan.FromMilliseconds(20), TimeSpan.FromSeconds(30)), this,
            "test-issuer", TimeSpan.FromSeconds(5), refill);
    }
    internal string Credential(bool badSignature = false, string purpose = "active_v2") => new JwtSecurityTokenHandler().WriteToken(
        new JwtSecurityToken("test-issuer", null, [new Claim("purpose", purpose), new Claim("jti", "test"), new Claim("webKey", "private-webkey")],
            signingCredentials: new SigningCredentials(new SymmetricSecurityKey(badSignature ? RandomNumberGenerator.GetBytes(64) : Key), SecurityAlgorithms.HmacSha256)));
    public Task<AuthorityReadResult> ReadAsync(string hash, Instant deadline, CancellationToken cancellationToken = default)
    {
        Interlocked.Increment(ref Calls);
        if (Read is not null) return Read(hash, deadline, cancellationToken);
        var now = SystemClock.Instance.GetCurrentInstant();
        return Task.FromResult(Status == AuthorityReadStatus.Found ? new AuthorityReadResult(Status,
            new AuthSessionProjection(hash, Key, Identity, new(now + Duration.FromMinutes(1), now + Duration.FromHours(1), null),
                new(Identity.AccountId, 1, 1, ["account.read"], false, now, now + Duration.FromMinutes(1), null, true), now)) : new(Status));
    }
    public Task AuditAsync(CancellationToken token) => Task.CompletedTask;
    public ValueTask DisposeAsync() { Admission.Quarantine(); CryptographicOperations.ZeroMemory(Key); return ValueTask.CompletedTask; }
    private sealed class NoCache : ICoherentCacheGetStore { public Task<byte[]?> GetAsync(string key, CancellationToken token) => throw new InvalidOperationException("Unadmitted."); }
}

internal static class RpcWire
{
    internal const string Path = "/treehammock.sessionvalidation.v1.SessionValidator/Validate";
    internal static ValidateRequest Request(string credential, string action = "backup.read") => new()
    { ContractVersion = 1, AccessCredential = ByteString.CopyFromUtf8(credential), RequestedAction = action, RequestId = Guid.NewGuid().ToString("N") };
    internal static async Task<(int Status, byte[] Body)> Call(HttpClient http, byte[] bytes, string? timeout = "1500m", byte flag = 0, string? encoding = null, CancellationToken token = default)
    {
        var frame = new byte[bytes.Length + 5]; frame[0] = flag; BinaryPrimitives.WriteInt32BigEndian(frame.AsSpan(1), bytes.Length); bytes.CopyTo(frame, 5);
        using var request = new HttpRequestMessage(HttpMethod.Post, Path) { Version = HttpVersion.Version20, VersionPolicy = HttpVersionPolicy.RequestVersionExact, Content = new ByteArrayContent(frame) };
        request.Content.Headers.ContentType = new("application/grpc"); request.Headers.Add("TE", "trailers");
        if (timeout is not null) request.Headers.Add("grpc-timeout", timeout);
        if (encoding is not null) request.Headers.Add("grpc-encoding", encoding);
        using var response = await http.SendAsync(request, token); var body = await response.Content.ReadAsByteArrayAsync(token);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode); Assert.Equal("no-store", response.Headers.CacheControl!.ToString());
        var headers = response.TrailingHeaders.TryGetValues("grpc-status", out var values) ? values : response.Headers.GetValues("grpc-status");
        return (int.Parse(headers.Single(), System.Globalization.CultureInfo.InvariantCulture), body);
    }
    internal static ValidateReply Reply(byte[] frame)
    {
        Assert.True(frame.Length >= 5); Assert.Equal(0, frame[0]); Assert.Equal(frame.Length - 5, BinaryPrimitives.ReadInt32BigEndian(frame.AsSpan(1)));
        return ValidateReply.Parser.ParseFrom(frame.AsSpan(5).ToArray());
    }
}
