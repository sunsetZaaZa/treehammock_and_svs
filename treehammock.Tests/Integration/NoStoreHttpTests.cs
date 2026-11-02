using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Microsoft.AspNetCore.Mvc.Testing;
using treehammock.Rigging.Authorization;
using treehammock.Tests.Infrastructure;

namespace treehammock.Tests.Integration;

// Actual Program pipeline and HTTP MVC; authority/cache/JWT are declared substitutes.
public sealed class Cor23ENoStoreHttpTests
{
    internal static void AssertPrivate(HttpResponseMessage response)
    {
        Assert.NotNull(response.Headers.CacheControl); Assert.True(response.Headers.CacheControl!.NoStore);
        Assert.False(response.Headers.CacheControl.Public); Assert.Null(response.Headers.CacheControl.MaxAge);
        Assert.Contains(response.Headers.Pragma, value => value.Name == "no-cache");
        Assert.NotNull(response.Content.Headers.Expires);
        Assert.True(response.Content.Headers.Expires <= DateTimeOffset.UnixEpoch);
    }
    internal static HttpRequestMessage Request(HttpMethod method, string path, string? token = null, bool bearer = false)
    {
        var request = new HttpRequestMessage(method,path);
        if (token is not null)
        {
            if (bearer) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer",token);
            else request.Headers.Add("AccessToken",token);
        }
        return request;
    }
    private static TreehammockWebApplicationFactory Factory(Cor23EAuthorityFixture authority)
        => new(Cor23EAuthorityFixture.Settings(),authority.Configure);

    [Theory]
    [InlineData(false, "/account/view")] [InlineData(true, "/account/view")]
    [InlineData(false, "/account/sessions")] [InlineData(true, "/account/sessions")]
    public async Task Actual_profile_and_session_success_and_credential_control_headers_are_no_store(bool bearer, string route)
    {
        var authority = new Cor23EAuthorityFixture(); using var factory = Factory(authority); using var client = factory.CreateClient();
        using var request = Request(HttpMethod.Get,route,Cor23EAuthorityFixture.FirstToken,bearer);
        using var response = await client.SendAsync(request); Assert.Equal(HttpStatusCode.OK,response.StatusCode); AssertPrivate(response);
        Assert.Equal(authority.Subjects[Cor23EAuthorityFixture.FirstToken].familyId.ToString("D"), response.Headers.GetValues(SessionProtocol.FamilyHeader).Single());
    }

    [Theory]
    [InlineData(null, false)] [InlineData("invalid-token", false)] [InlineData("invalid-token", true)]
    public async Task Authentication_denials_are_no_store(string? token, bool bearer)
    {
        using var factory = Factory(new()); using var client = factory.CreateClient();
        using var request = Request(HttpMethod.Get,"/account/view",token,bearer); using var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.Unauthorized,response.StatusCode); AssertPrivate(response);
        if(token is not null) Assert.Equal(AccessTokenHashUtility.Hash(token),response.Headers.GetValues(SessionProtocol.ClearTokenHashHeader).Single());
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task Validation_and_refresh_precondition_failures_are_no_store(bool refresh)
    {
        using var factory = Factory(new()); using var client = factory.CreateClient();
        using var request = Request(HttpMethod.Post,refresh ? "/account/refresh" : "/account/requestaccess");
        request.Content = new StringContent(refresh ? "{\"protocolVersion\":2,\"sessionId\":\"11111111-1111-1111-1111-111111111111\",\"generation\":1,\"refreshToken\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}" : "{",Encoding.UTF8,"application/json");
        using var response = await client.SendAsync(request);
        Assert.Equal(refresh ? HttpStatusCode.PreconditionRequired : HttpStatusCode.BadRequest,response.StatusCode); AssertPrivate(response);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task Anonymous_confirmation_HTML_with_credentials_is_no_store(bool bearer)
    {
        using var factory = Factory(new()); using var client = factory.CreateClient();
        using var request = Request(HttpMethod.Get,"/account/adjust/email/verify?payload=fixture-proof",Cor23EAuthorityFixture.FirstToken,bearer);
        using var response = await client.SendAsync(request); Assert.Equal(HttpStatusCode.OK,response.StatusCode); AssertPrivate(response);
        Assert.Equal("text/html",response.Content.Headers.ContentType!.MediaType);
        Assert.Contains("fixture-proof",await response.Content.ReadAsStringAsync());
        Assert.True(response.Headers.Contains(SessionProtocol.FamilyHeader));
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task Dependency_and_unexpected_authentication_failures_are_no_store_and_sanitized(bool unexpected)
    {
        var authority = new Cor23EAuthorityFixture(); if(unexpected) authority.UnexpectedAuthenticationFailure(); else authority.Outage();
        using var factory = Factory(authority); using var client = factory.CreateClient();
        using var request = Request(HttpMethod.Get,"/account/sessions",Cor23EAuthorityFixture.FirstToken);
        using var response = await client.SendAsync(request);
        Assert.Equal(unexpected ? HttpStatusCode.InternalServerError : HttpStatusCode.ServiceUnavailable,response.StatusCode); AssertPrivate(response);
        string body = await response.Content.ReadAsStringAsync(); Assert.DoesNotContain("credential-body-must-not-leak",body);
        Assert.Contains(unexpected ? "INTERNAL_SERVER_ERROR" : "DEPENDENCY_UNAVAILABLE",body);
    }

    [Fact]
    public async Task Unknown_routes_and_method_denials_are_no_store()
    {
        using var factory = Factory(new()); using var client = factory.CreateClient();
        using(var response = await client.GetAsync("/does-not-exist")) { Assert.Equal(HttpStatusCode.NotFound,response.StatusCode); AssertPrivate(response); }
        using(var response = await client.GetAsync("/account/security-operations/status")) { Assert.Equal(HttpStatusCode.PreconditionRequired,response.StatusCode); AssertPrivate(response); }
        using(var response = await client.GetAsync("/account/refresh")) { Assert.Equal(HttpStatusCode.MethodNotAllowed,response.StatusCode); AssertPrivate(response); }
    }
}
