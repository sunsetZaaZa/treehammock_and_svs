using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NodaTime;
using NodaTime.Text;
using Svs12.Golden;
using treehammock.Rigging.Authorization;
using treehammock.Rigging.Config;
using treehammock.RiggingSupport.Status;
using treehammock.RiggingSupport.Enum;
using treehammock.Services;
using Xunit;
namespace treehammock.Tests.Unit;
public sealed class Svs12CurrentIssuerTests
{
    private static JsonWebTokenUtility Utility(string issuer="test-issuer")=>new(NullLogger<JsonWebTokenUtility>.Instance,Options.Create(new JWTSettings{JsonWebTokenIssuer=issuer}));
    private static Dictionary<string,string> Mint()
    {
        var key=TreehammockParityFixtures.Key();string issued=Utility().GenerateAccessToken(key,"svs12-public-fixture");
        var result=new Dictionary<string,string>{{"issued",issued},{"preauth",Utility().GenerateAccessToken(key,"svs12-public-fixture","preauth_2fa")},{"wrong-key",Utility().GenerateAccessToken(Enumerable.Repeat((byte)64,64).ToArray(),"svs12-public-fixture")},{"wrong-issuer",Utility("wrong-issuer").GenerateAccessToken(key,"svs12-public-fixture")},{"opaque-refresh",Convert.ToBase64String(new byte[32])},{"malformed","not.a.valid.jws"}};
        foreach(string kind in new[]{"hs384","unsigned","missing-jti","empty-jti","missing-purpose","empty-purpose","missing-webkey","empty-webkey","expired-exp","future-nbf"})
        {
            var claims=new JwtSecurityTokenHandler().ReadJwtToken(issued).Payload.ToDictionary(x=>x.Key,x=>x.Value);
            string claim=kind.EndsWith("webkey",StringComparison.Ordinal)?"webKey":kind.EndsWith("purpose",StringComparison.Ordinal)?"purpose":"jti";
            if(kind.StartsWith("missing-",StringComparison.Ordinal))claims.Remove(claim);
            if(kind.StartsWith("empty-",StringComparison.Ordinal))claims[claim]=" ";
            if(kind=="expired-exp")claims["exp"]=1L;if(kind=="future-nbf")claims["nbf"]=4000000000L;
            string B64(byte[] b)=>Convert.ToBase64String(b).TrimEnd('=').Replace('+','-').Replace('/','_');
            string alg=kind=="hs384"?"HS384":kind=="unsigned"?"none":"HS256";
            string body=B64(JsonSerializer.SerializeToUtf8Bytes(new{alg,typ="JWT"}))+"."+B64(JsonSerializer.SerializeToUtf8Bytes(claims));
            result[kind]=body+"."+(kind=="unsigned"?"":B64(kind=="hs384"?HMACSHA384.HashData(key,Encoding.UTF8.GetBytes(body)):HMACSHA256.HashData(key,Encoding.UTF8.GetBytes(body))));
        }
        CryptographicOperations.ZeroMemory(key);return result;
    }
    [Fact] public async Task Current_source_issuer_exports_real_no_exp_tokens_and_matches_every_golden_token_case()
    {
        var tokens=Mint();var parsed=new JwtSecurityTokenHandler().ReadJwtToken(tokens["issued"]);
        Assert.False(parsed.Payload.ContainsKey("exp"));Assert.False(parsed.Payload.ContainsKey("nbf"));Assert.Equal("HS256",parsed.Header.Alg);Assert.True(Guid.TryParseExact(parsed.Id,"N",out _));
        Assert.Equal("active_v2",parsed.Claims.Single(c=>c.Type=="purpose").Value);Assert.Equal("svs12-public-fixture",parsed.Claims.Single(c=>c.Type=="webKey").Value);
        var now=InstantPattern.ExtendedIso.Parse(TreehammockParityFixtures.Corpus.Now).Value;
        foreach(var c in TreehammockParityFixtures.Corpus.Cases)
        {
            var actual=await Utility().ValidateAccessToken(tokens[c.Token],TreehammockParityFixtures.Key(),now,now+Duration.FromTicks(c.AccessTicks));
            string status=actual.Item1 switch{IntraMessage.TOKEN_PASSED_VALIDATION=>"Passed",IntraMessage.TOKEN_AT_EXPIRATION=>"AtExpiration",IntraMessage.TOKEN_EXPIRED_VALIDATION=>"Expired",IntraMessage.TOKEN_VALIDATION_MALFORMED=>"Malformed",IntraMessage.TOKEN_THREW_EXCEPTION_IN_VALIDATION=>"UnexpectedException",_=>"Failed"};
            Assert.True(status==c.ExpectedToken,c.Id+": "+status);TreehammockParityFixtures.Report("issuer-"+c.Id,new{Id=c.Id,Token=status});
        }
        if(Environment.GetEnvironmentVariable("SVS12_EXPORT_TOKENS") is {} path)File.WriteAllText(path,JsonSerializer.Serialize(new{format="SVS12Tokens.v1",syntheticOnly=true,origin="Actual current JsonWebTokenUtility.GenerateAccessToken; negative variants derived from its issued JWS",tokens},TreehammockParityFixtures.Json));
    }
    [Theory]
    [InlineData("2024-01-31T12:00:00Z","MONTHLY",1,"2024-02-29T12:00:00Z")]
    [InlineData("2024-01-31T12:00:00Z","MONTHLY",2,"2024-03-31T12:00:00Z")]
    [InlineData("2023-01-31T12:00:00Z","MONTHLY",1,"2023-02-28T12:00:00Z")]
    [InlineData("2024-02-29T12:00:00Z","YEAR",1,"2025-02-28T12:00:00Z")]
    [InlineData("2024-02-29T12:00:00Z","YEAR",4,"2028-02-29T12:00:00Z")]
    [InlineData("2026-03-07T08:30:00Z","DAILY",1,"2026-03-08T08:30:00Z")]
    [InlineData("2026-10-31T07:30:00Z","DAILY",1,"2026-11-01T07:30:00Z")]
    [InlineData("2024-01-31T12:00:00Z","QUARTERYEAR",1,"2024-04-30T12:00:00Z")]
    [InlineData("2024-01-31T12:00:00Z","SEMIYEAR",1,"2024-07-31T12:00:00Z")]
    [InlineData("2024-01-31T12:00:00Z","TRIQUARTERYEAR",1,"2024-10-31T12:00:00Z")]
    [InlineData("2024-01-31T12:00:00Z","INDEFINITE",1,null)]
    public void Current_calendar_uses_original_UTC_anchor_and_exact_cycle_boundary(string start,string term,int cycle,string? end)
    {
        var anchor=InstantPattern.ExtendedIso.Parse(start).Value;var duration=Enum.Parse<DayDuration>(term);var boundary=CalendarTermCalculator.Boundary(anchor,duration,cycle);
        Assert.Equal(end,boundary is {} b?InstantPattern.ExtendedIso.Format(b):null);
        if(boundary is {} at){Assert.Equal(cycle,CalendarTermCalculator.CycleAt(anchor,duration,cycle+1,null,at-Duration.FromTicks(1)));Assert.Equal(cycle+1,CalendarTermCalculator.CycleAt(anchor,duration,cycle+1,null,at));Assert.Equal(0,CalendarTermCalculator.CycleAt(anchor,duration,cycle+1,at,at));}
    }
}
