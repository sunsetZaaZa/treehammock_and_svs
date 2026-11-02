using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using NodaTime;
using Treehammock.SessionValidation.Core;

namespace Treehammock.SessionValidation.UnitTests;

internal static class TestSessions
{
    internal static readonly Instant Now = Instant.FromUtc(2026, 10, 17, 1, 0);
    internal const string Issuer = "svs02.test";
    internal static byte[] Key() => Enumerable.Repeat((byte)93, 64).ToArray();
    internal static readonly SessionIdentity Identity = new(Guid.Parse("11111111-1111-4111-8111-111111111111"),
        Guid.Parse("22222222-2222-4222-8222-222222222222"), 5, 2,
        Guid.Parse("33333333-3333-4333-8333-333333333333"), Guid.Parse("44444444-4444-4444-8444-444444444444"));
    internal static EntitlementPolicyInputs Entitlements(long version = 4, int tier = 1,
        string[]? capabilities = null, bool rights = true, Instant? evaluated = null,
        Instant? boundary = null, bool grants = true) => new(Identity.AccountId, version, tier,
        capabilities ?? new[] { "account.read", "account.manage" }, rights, evaluated ?? Now - Duration.FromSeconds(1),
        boundary ?? Now + Duration.FromMinutes(10), null, grants);
    internal static SessionValidationInputs Inputs() => new(Identity, Identity,
        new(Now + Duration.FromMinutes(5), Now + Duration.FromHours(1), null),
        Entitlements(), AccountEligibility.Eligible, "account.read", Now, Now + Duration.FromSeconds(5));
    internal static string Mint(string kind = "valid")
    {
        var claims = new List<Claim>();
        if (kind != "missing-webkey") claims.Add(new("webKey", kind == "empty-webkey" ? " " : "web-canary-not-for-logs"));
        if (kind != "missing-purpose") claims.Add(new("purpose", kind switch
        {
            "preauth" => "preauth_2fa", "wrong-purpose" => "other", "empty-purpose" => " ", _ => "active_v2"
        }));
        if (kind != "missing-jti") claims.Add(new("jti", kind == "empty-jti" ? " " : "synthetic-id"));
        var credentials = kind == "unsigned" ? null : new SigningCredentials(
            new SymmetricSecurityKey(kind == "wrong-key" ? Enumerable.Repeat((byte)64, 64).ToArray() : Key()),
            kind switch { "hs384" => SecurityAlgorithms.HmacSha384, "hs512" => SecurityAlgorithms.HmacSha512, _ => SecurityAlgorithms.HmacSha256 });
        var token = new JwtSecurityToken(kind == "wrong-issuer" ? "other.test" : Issuer, null, claims,
            notBefore: null, expires: kind == "expired-jwt-claim" ? Now.Minus(Duration.FromDays(10)).ToDateTimeUtc() : null,
            signingCredentials: credentials);
        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
