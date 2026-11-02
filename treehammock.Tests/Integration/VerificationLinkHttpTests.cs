using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using treehammock.Services;
using treehammock.Tests.Infrastructure;
using treehammock.Tests.Unit;

namespace treehammock.Tests.Integration;

public sealed class Cor23GVerificationLinkHttpTests
{
    internal static async Task FollowAllAsync(HttpClient client,Cor23GLinkFixture links,string origin,CancellationToken token)
    {
        foreach(var intent in links.Delivery.Intents)
        {
            var uri=new Uri(intent.Payload.Value);Assert.Equal(origin,uri.GetLeftPart(UriPartial.Authority));
            string payload=QueryHelpers.ParseQuery(uri.Query)["payload"].ToString();Assert.NotEmpty(payload);
            string hash=intent.Purpose=="delete"?treehammock.Rigging.Security.SecretHashUtility.HashLookupToken(payload):treehammock.Rigging.Security.AccountVerificationTokenUtility.HashToken(payload);
            Assert.Equal(intent.ProofHash,hash);
            using var get=new HttpRequestMessage(HttpMethod.Get,uri.PathAndQuery);
            get.Headers.TryAddWithoutValidation("X-Forwarded-Host","evil.example.test");get.Headers.TryAddWithoutValidation("Forwarded","host=evil.example.test;proto=http");
            using var response=await client.SendAsync(get,token);Assert.Equal(200,(int)response.StatusCode);Cor23ENoStoreHttpTests.AssertPrivate(response);
            string body=await response.Content.ReadAsStringAsync(token);
            if(intent.Purpose=="verify")
                Assert.Equal(File.ReadAllText(Path.Combine(Cor23GPublicOriginTests.ProjectRoot(),"html_templates/account_verification/success.html")),body);
            else if(intent.Purpose=="email")
            {
                Assert.Equal(0,links.EmailConfirmed);Assert.Contains("method=\"post\"",body);Assert.Contains("Confirm email change",body);Assert.Contains(payload,body);
                // A scanner GET remains read-only; explicit POST owns the existing proof-consumption contract.
                using var again=await client.GetAsync(uri.PathAndQuery,token);Assert.Equal(200,(int)again.StatusCode);Assert.Equal(0,links.EmailConfirmed);
                using var post=new HttpRequestMessage(HttpMethod.Post,uri.AbsolutePath){Content=new FormUrlEncodedContent(new Dictionary<string,string>{{"verifyToken",payload}})};
                using var confirmed=await client.SendAsync(post,token);Assert.Equal(200,(int)confirmed.StatusCode);Cor23ENoStoreHttpTests.AssertPrivate(confirmed);
                using var result=JsonDocument.Parse(await confirmed.Content.ReadAsStringAsync(token));Assert.True(result.RootElement.GetProperty("success").GetBoolean());Assert.Equal(1,links.EmailConfirmed);
            }
            else
            {
                Assert.Equal(0,links.DeleteVerified);Assert.Contains("method=\"post\"",body);
                using var again=await client.GetAsync(uri.PathAndQuery,token);Assert.Equal(200,(int)again.StatusCode);Assert.Equal(0,links.DeleteVerified);
                var fields=System.Text.RegularExpressions.Regex.Matches(body,"name=\"([^\"]+)\" value=\"([^\"]*)\"")
                    .ToDictionary(m=>m.Groups[1].Value,m=>System.Net.WebUtility.HtmlDecode(m.Groups[2].Value));
                using var post=new FormUrlEncodedContent(fields);
                using var confirmed=await client.PostAsync(uri.AbsolutePath,post,token);
                Assert.Equal(200,(int)confirmed.StatusCode);Cor23ENoStoreHttpTests.AssertPrivate(confirmed);
                using var result=JsonDocument.Parse(await confirmed.Content.ReadAsStringAsync(token));Assert.True(result.RootElement.GetProperty("success").GetBoolean());Assert.Equal("ACCOUNT_DELETE_VERIFIED",result.RootElement.GetProperty("code").GetString());
            }
        }
        Assert.Equal(2,links.Verified);Assert.Equal(1,links.EmailConfirmed);Assert.Equal(1,links.DeleteVerified);
    }
    [Theory]
    [InlineData("LocalHttps","https://localhost:5001")]
    [InlineData("Container","http://localhost:5001")]
    [InlineData("ContainerReverseProxy","http://localhost:8080")]
    [InlineData("ReverseProxy","https://api.example.test")]
    public async Task Actual_Program_captures_all_four_configured_origins_and_follows_real_confirmation_routes(string profile,string origin)
    {
        var links=new Cor23GLinkFixture();var settings=Cor23EAuthorityFixture.Settings();settings["RegistrationSettings:PublicOrigin"]=origin;settings["AbuseControlSettings:Enabled"]="false";
        using var factory=new TreehammockWebApplicationFactory(settings,services=>Cor23GPublicHttpFixture.Configure(services,links));
        using var client=factory.CreateClient();
        var accessor=factory.Services.GetRequiredService<IHttpContextAccessor>();accessor.HttpContext=new DefaultHttpContext();accessor.HttpContext.Request.Host=new("evil.example.test");accessor.HttpContext.Request.Headers["X-Forwarded-Host"]="evil.example.test";
        await links.CaptureAsync((AccountService)factory.Services.GetRequiredService<IAccountService>(),TestContext.Current.CancellationToken);
        await FollowAllAsync(client,links,origin,TestContext.Current.CancellationToken);
    }
    [Theory]
    [InlineData("LocalHttps")] [InlineData("Container")] [InlineData("ContainerReverseProxy")] [InlineData("ReverseProxy")]
    public async Task Owned_public_listener_and_proxy_follow_captured_links_with_exact_TLS_HTTP_authority_and_proof_flow(string profile)
    {
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);deadline.CancelAfter(TimeSpan.FromSeconds(30));
        await using var host=await Cor23GPublicHttpFixture.StartAsync(profile,deadline.Token);
        using var request=new HttpRequestMessage(HttpMethod.Post,"/fixture/generate");
        request.Headers.TryAddWithoutValidation("X-Forwarded-Host","evil.example.test");request.Headers.TryAddWithoutValidation("Forwarded","host=evil.example.test;proto=http");
        if(profile is "Container" or "ContainerReverseProxy")request.Headers.Host="evil.example.test";
        using var response=await host.Client.SendAsync(request,deadline.Token);Assert.Equal(200,(int)response.StatusCode);
        Assert.Equal(profile is "LocalHttps" or "ReverseProxy"?"https":"http",new Uri(host.PublicOrigin).Scheme);
        await FollowAllAsync(host.Client,host.Links,host.PublicOrigin,deadline.Token);
    }
}
