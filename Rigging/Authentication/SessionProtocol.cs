using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using NodaTime;
using treehammock.DataLayer.Cache;
using treehammock.Entities;
using treehammock.Models.Authentication;

namespace treehammock.Rigging.Authorization;

public static class SessionProtocol
{
    public const int Version = Treehammock.SessionValidation.Core.SessionIdentity.CurrentProtocol;
    public const long MaximumGeneration = Treehammock.SessionValidation.Core.SessionIdentity.MaximumGeneration; // exact JavaScript integer
    public const string RefreshPath = "/account/refresh";
    public const string VersionHeader = "Session-Protocol";
    public const string FamilyHeader = "Session-Family";
    public const string GenerationHeader = "Session-Generation";
    public const string ClearTokenHashHeader = "Session-Clear-Token-Hash";

    // This is an opaque client credential, distinct from both the access JWS and
    // its server-only signing key (historically named refreshToken in Session).
    // Only its SHA-256 verifier is persisted in the sessions row.
    public static string RefreshCredential(byte[] signingKey, Guid tokenIdentity)
    {
        byte[] material = HMACSHA256.HashData(signingKey,
            Encoding.UTF8.GetBytes("treehammock:refresh:v2:" + tokenIdentity.ToString("N")));
        try { return Convert.ToBase64String(material).TrimEnd('=').Replace('+', '-').Replace('/', '_'); }
        finally { CryptographicOperations.ZeroMemory(material); }
    }

    public static SessionCredential Credentials(ActiveSession session) => new(
        Version, session.familyId, session.generation,
        RefreshCredential(session.refreshToken, session.securityStamp),
        session.accessExpiration, session.EffectiveSessionExpiration, session.entitlements);

    public static void WriteHeaders(HttpResponse response, ActiveSession session)
    {
        treehammock.Rigging.Hosting.SecurityResponseCacheMiddleware.Apply(response);
        response.Headers[VersionHeader] = Version.ToString(CultureInfo.InvariantCulture);
        response.Headers[FamilyHeader] = session.familyId.ToString("D");
        response.Headers[GenerationHeader] = session.generation.ToString(CultureInfo.InvariantCulture);
    }

    public static ActiveSession FromSession(Session session) => new(
        session.accountId, session.refreshToken, session.refreshes ?? 0,
        session.createdOn, session.sessionLifespan ?? throw new InvalidOperationException("Missing family lifetime."),
        session.accessExpiration, session.sessionExpiration, session.cutOff, session.features,
        session.securityStamp, session.accountSecurityStamp, session.familyId, session.generation, session.protocolVersion, session.entitlements);
}
