using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using NodaTime;
using treehammock.Rigging.Authorization;
using treehammock.Tests.Infrastructure;

namespace treehammock.Tests.Integration;

public sealed class Svs03HttpParityTests
{
    public sealed record Golden(int Status,string Code,bool ClearToken,bool Protocol,bool HashHeader,bool CallsController);
    private static readonly Dictionary<string,Golden> Goldens=JsonSerializer.Deserialize<Dictionary<string,Golden>>(
        File.ReadAllText(Path.Combine(AppContext.BaseDirectory,"Fixtures/LegacyParity/http-goldens.json")))!;

    public static IEnumerable<object[]> Matrix()
    {
        foreach(string scenario in Goldens.Keys)
        foreach(bool warm in new[]{false,true})
        foreach(bool bearer in new[]{false,true})
        {
            if(!warm && scenario is "trust-null" or "trust-failed")continue;
            if(warm && scenario is "cache-write-false" or "cache-write-throws" or "malformed-db")continue;
            yield return new object[]{scenario,warm,bearer};
        }
    }

    [Theory]
    [MemberData(nameof(Matrix))]
    public async Task Actual_Program_with_real_JWS_matches_public_status_and_header_goldens(string scenario,bool warm,bool bearer)
    {
        var state=new Svs03SessionFixture(warm,scenario);
        using var factory=new TreehammockWebApplicationFactory(Svs03SessionFixture.Settings(),state.Configure);
        using var client=factory.CreateClient();
        using var request=Request(state,scenario=="no-credential"?null:state.Credential,bearer);
        using var response=await client.SendAsync(request,TestContext.Current.CancellationToken);
        await AssertGolden(response,Goldens[scenario],state,scenario=="no-credential"?null:state.Credential);
        Assert.Equal(Goldens[scenario].CallsController?1:0,state.Lists);
        if(scenario=="active")
        {
            Assert.False(new JwtSecurityTokenHandler().ReadJwtToken(state.Credential).Payload.ContainsKey("exp"));
            Assert.Equal(warm?0:1,state.Gets);Assert.Equal(warm?1:0,state.Trusts);Assert.Equal(1,state.Verifies);
            Assert.Equal(warm?0:1,state.Writes);
            var events=state.Events.ToArray();
            Assert.True(Array.IndexOf(events,warm?"db.trust":"db.get")<Array.IndexOf(events,"token.verify"));
            Assert.True(Array.IndexOf(events,"token.verify")<Array.IndexOf(events,"controller.list"));
            if(!warm)
            {
                Assert.True(Array.IndexOf(events,"token.verify")<Array.IndexOf(events,"cache.set"));
                Assert.True(state.LastTtl>TimeSpan.Zero);Assert.True(state.LastTtl<=TimeSpan.FromMinutes(2));
            }
        }
        if(scenario is "wrong-key" or "wrong-algorithm" or "wrong-issuer" or "missing-purpose" or "missing-jti" or "missing-webkey" or "preauth" or "opaque-refresh" or "malformed")
            Assert.Equal(0,state.Writes);
        if(scenario=="cache-corrupt")Assert.Equal(1,state.Revokes);
    }

    [Theory]
    [InlineData(false,"refresh")][InlineData(true,"refresh")]
    [InlineData(false,"second-login")][InlineData(true,"second-login")]
    [InlineData(false,"logout")][InlineData(true,"logout")]
    [InlineData(false,"logout-all")][InlineData(true,"logout-all")]
    public async Task Following_requests_recheck_authority_after_a_simulated_commit_even_with_stale_cache(bool warm,string change)
    {
        var state=new Svs03SessionFixture(warm);string old=state.Credential;
        using var factory=new TreehammockWebApplicationFactory(Svs03SessionFixture.Settings(),state.Configure);using var client=factory.CreateClient();
        using(var req=Request(state,old))using(var response=await client.SendAsync(req,TestContext.Current.CancellationToken))await AssertGolden(response,Goldens["active"],state,old);
        if(change is "logout" or "logout-all")state.Revoked=true;else state.Rotate(change=="second-login");
        int callsBefore=state.Lists;
        using(var req=Request(state,old))using(var response=await client.SendAsync(req,TestContext.Current.CancellationToken))await AssertGolden(response,Goldens["authority-denied"],state,old);
        Assert.Equal(callsBefore,state.Lists);
        if(change is "refresh" or "second-login")
            using(var req=Request(state,state.Credential))using(var response=await client.SendAsync(req,TestContext.Current.CancellationToken))await AssertGolden(response,Goldens["active"],state,state.Credential);
    }

    [Theory]
    [InlineData("generation")][InlineData("family")][InlineData("session-stamp")][InlineData("account-stamp")]
    public async Task Current_authority_rejects_stale_cached_protocol_identity(string field)
    {
        var state=new Svs03SessionFixture();
        if(field=="generation")state.Current.generation++;
        if(field=="family")state.Current.familyId=Guid.NewGuid();
        if(field=="session-stamp")state.Current.securityStamp=Guid.NewGuid();
        if(field=="account-stamp")state.Current.accountSecurityStamp=Guid.NewGuid();
        using var factory=new TreehammockWebApplicationFactory(Svs03SessionFixture.Settings(),state.Configure);using var client=factory.CreateClient();
        using var req=Request(state,state.Credential);using var response=await client.SendAsync(req,TestContext.Current.CancellationToken);
        await AssertGolden(response,Goldens["authority-denied"],state,state.Credential);Assert.Equal(0,state.Verifies);Assert.Equal(0,state.Lists);
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Entitlement_revocation_takes_effect_on_the_next_request(bool warm)
    {
        var state=new Svs03SessionFixture(warm);
        using var factory=new TreehammockWebApplicationFactory(Svs03SessionFixture.Settings(),state.Configure);using var client=factory.CreateClient();
        using(var req=Request(state,state.Credential))using(var response=await client.SendAsync(req,TestContext.Current.CancellationToken))await AssertGolden(response,Goldens["active"],state,state.Credential);
        state.Current.entitlements=state.Current.entitlements! with {Version=2,Capabilities=[]};
        using(var req=Request(state,state.Credential))using(var response=await client.SendAsync(req,TestContext.Current.CancellationToken))await AssertGolden(response,Goldens["capability-denied"],state,state.Credential);
        Assert.Equal(1,state.Lists);
    }

    [Theory]
    [InlineData("bearer-wins",200)][InlineData("bad-bearer-wins",401)]
    [InlineData("basic-fallback",200)][InlineData("empty-bearer-fallback",200)]
    public async Task Existing_transport_precedence_is_preserved(string choice,int status)
    {
        var state=new Svs03SessionFixture();using var factory=new TreehammockWebApplicationFactory(Svs03SessionFixture.Settings(),state.Configure);using var client=factory.CreateClient();
        using var request=new HttpRequestMessage(HttpMethod.Get,"/account/sessions");
        request.Headers.TryAddWithoutValidation("AccessToken",choice=="bearer-wins"?"invalid-secondary":state.Credential);
        request.Headers.TryAddWithoutValidation("Authorization",choice switch
        {"bearer-wins"=>"bEaReR "+state.Credential,"bad-bearer-wins"=>"Bearer invalid-primary","basic-fallback"=>"Basic unused",_=>"Bearer "});
        using var response=await client.SendAsync(request,TestContext.Current.CancellationToken);
        Assert.Equal(status,(int)response.StatusCode);Cor23ENoStoreHttpTests.AssertPrivate(response);
        Assert.Equal(AccessTokenHashUtility.Hash(choice=="bad-bearer-wins"?"invalid-primary":state.Credential),response.Headers.GetValues(SessionProtocol.ClearTokenHashHeader).Single());
    }

    [Fact]
    public async Task Authenticated_response_is_not_reused_for_a_later_anonymous_request()
    {
        var state=new Svs03SessionFixture();using var factory=new TreehammockWebApplicationFactory(Svs03SessionFixture.Settings(),state.Configure);using var client=factory.CreateClient();
        using(var request=Request(state,state.Credential))using(var response=await client.SendAsync(request,TestContext.Current.CancellationToken))await AssertGolden(response,Goldens["active"],state,state.Credential);
        using(var response=await client.GetAsync("/account/sessions",TestContext.Current.CancellationToken))await AssertGolden(response,Goldens["no-credential"],state,null);
        Assert.Equal(1,state.Lists);
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Real_refresh_route_still_requires_its_independent_operation_credentials(bool bearer)
    {
        var state=new Svs03SessionFixture(scenario:"expired-access");
        using var factory=new TreehammockWebApplicationFactory(Svs03SessionFixture.Settings(),state.Configure);using var client=factory.CreateClient();
        using var request=Request(state,state.Credential,bearer);request.Method=HttpMethod.Post;request.RequestUri=new Uri("/account/refresh",UriKind.Relative);
        request.Content=new StringContent("{\"protocolVersion\":2,\"sessionId\":\"44444444-4444-4444-8444-444444444444\",\"generation\":7,\"refreshToken\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}",Encoding.UTF8,"application/json");
        using var response=await client.SendAsync(request,TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.PreconditionRequired,response.StatusCode);Cor23ENoStoreHttpTests.AssertPrivate(response);
        Assert.Contains("SECURITY_OPERATION_KEYS_REQUIRED",await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        Assert.Equal(0,state.Gets+state.Trusts+state.Verifies);Assert.False(response.Headers.Contains(SessionProtocol.ClearTokenHashHeader));
    }

    [Fact]
    public async Task Record_local_public_request_latency_without_claiming_an_approved_SLO()
    {
        var rows=new List<object>();
        foreach(bool warm in new[]{false,true})
        {
            var state=new Svs03SessionFixture(warm);using var factory=new TreehammockWebApplicationFactory(Svs03SessionFixture.Settings(),state.Configure);using var client=factory.CreateClient();
            var times=new List<double>();
            for(int i=0;i<110;i++)
            {
                using var req=Request(state,state.Credential);long started=Stopwatch.GetTimestamp();
                using var response=await client.SendAsync(req,TestContext.Current.CancellationToken);Assert.Equal(HttpStatusCode.OK,response.StatusCode);
                if(i>=10)times.Add(Stopwatch.GetElapsedTime(started).TotalMilliseconds);
            }
            times.Sort();rows.Add(new {mode=warm?"warm-with-current-DB-trust":"forced-cache-miss",samples=100,p50_ms=times[49],p95_ms=times[94],p99_ms=times[98],db_gets=state.Gets,db_trust=state.Trusts,verified=state.Verifies});
            Assert.Equal(110,state.Gets+state.Trusts);Assert.Equal(110,state.Verifies);
        }
        string? path=Environment.GetEnvironmentVariable("SVS03_EVIDENCE_DIRECTORY");
        if(path is not null)
        {
            Directory.CreateDirectory(path);await File.WriteAllTextAsync(Path.Combine(path,"http-latency.json"),JsonSerializer.Serialize(new
            {scope="Local in-memory TestServer + real JWS, stubbed authority/cache; startup excluded. Exploratory, not native/physical-host SLO qualification.",rows},new JsonSerializerOptions{WriteIndented=true}),TestContext.Current.CancellationToken);
        }
    }

    internal static HttpRequestMessage Request(Svs03SessionFixture state,string? token,bool bearer=true)
    {
        var request=new HttpRequestMessage(HttpMethod.Get,"/account/sessions");
        if(token is not null){if(bearer)request.Headers.Authorization=new AuthenticationHeaderValue("Bearer",token);else request.Headers.Add("AccessToken",token);}return request;
    }
    private static async Task AssertGolden(HttpResponseMessage response,Golden expected,Svs03SessionFixture state,string? token)
    {
        Assert.Equal(expected.Status,(int)response.StatusCode);Cor23ENoStoreHttpTests.AssertPrivate(response);
        Assert.Equal("no-store",response.Headers.CacheControl!.ToString());
        Assert.Equal("no-cache",Assert.Single(response.Headers.Pragma).ToString());
        Assert.Equal("Thu, 01 Jan 1970 00:00:00 GMT",response.Content.Headers.GetValues("Expires").Single());
        string body=await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);using var json=JsonDocument.Parse(body);
        Assert.Equal(expected.Status,json.RootElement.GetProperty("statusCode").GetInt32());Assert.Equal(expected.Code,json.RootElement.GetProperty("code").GetString());
        Assert.Equal(expected.Status==200,json.RootElement.GetProperty("success").GetBoolean());
        Assert.Equal(expected.ClearToken,response.Headers.Contains("AppStatus"));
        if(expected.ClearToken)Assert.Equal("CLIENT_CLEAR_ACCESS_TOKEN",response.Headers.GetValues("AppStatus").Single());
        foreach(string header in new[]{SessionProtocol.VersionHeader,SessionProtocol.FamilyHeader,SessionProtocol.GenerationHeader})Assert.Equal(expected.Protocol,response.Headers.Contains(header));
        if(expected.Protocol)
        {
            Assert.Equal("2",response.Headers.GetValues(SessionProtocol.VersionHeader).Single());
            Assert.Equal(state.Current.familyId.ToString("D"),response.Headers.GetValues(SessionProtocol.FamilyHeader).Single());
            Assert.Equal(state.Current.generation.ToString(System.Globalization.CultureInfo.InvariantCulture),response.Headers.GetValues(SessionProtocol.GenerationHeader).Single());
        }
        Assert.Equal(expected.HashHeader,response.Headers.Contains(SessionProtocol.ClearTokenHashHeader));
        if(expected.HashHeader)Assert.Equal(AccessTokenHashUtility.Hash(token!),response.Headers.GetValues(SessionProtocol.ClearTokenHashHeader).Single());
        Assert.DoesNotContain(Convert.ToBase64String(state.Current.refreshToken),body);if(token is not null)Assert.DoesNotContain(token,body);
        if(expected.Status!=200)Assert.DoesNotContain(state.Current.accountId.ToString("D"),body);
    }
}
