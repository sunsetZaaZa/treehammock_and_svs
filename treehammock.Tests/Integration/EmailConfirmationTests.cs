using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using NSubstitute;
using Shouldly;
using treehammock.RiggingSupport.Status;
using treehammock.Services;
using treehammock.Tests.Infrastructure;
namespace treehammock.Tests.Integration;

// Routed HTTP contract with explicit account service substitution. Native COR17 owns SQL effects.
public class Cor17EmailConfirmationTests
{
    [Fact]
    public async Task Scanner_GETs_leave_service_untouched_then_manual_form_POST_performs_one_confirmation()
    {
        var service=Substitute.For<IAccountService>();
        service.CompleteEmailChange("mailbox-proof",Arg.Any<CancellationToken>()).Returns(new AccountAdjustResult(true,"ACCOUNT_ADJUST_SUCCEEDED",Guid.NewGuid()));
        using var factory=new TreehammockWebApplicationFactory(TestConfiguration.ValidSettings(),services=>{services.RemoveAll<IAccountService>();services.AddSingleton(service);});
        using var client=factory.CreateClient(new WebApplicationFactoryClientOptions{BaseAddress=new Uri("https://localhost.test"),AllowAutoRedirect=false});
        string page="";
        for(int i=0;i<3;i++) {
            using var response=await client.GetAsync("/account/adjust/email/verify?payload=mailbox-proof");response.StatusCode.ShouldBe(HttpStatusCode.OK);
            response.Content.Headers.ContentType!.MediaType.ShouldBe("text/html");response.Headers.CacheControl!.NoStore.ShouldBeTrue();response.Headers.GetValues("Referrer-Policy").Single().ShouldBe("no-referrer");
            page=await response.Content.ReadAsStringAsync();
        }
        await service.DidNotReceiveWithAnyArgs().CompleteEmailChange(default!,default);
        string Field(string name)=>WebUtility.HtmlDecode(Regex.Match(page,"name=\\\""+name+"\\\" value=\\\"([^\\\"]+)\\\"").Groups[1].Value);
        using var posted=await client.PostAsync("/account/adjust/email/verify",new FormUrlEncodedContent(new Dictionary<string,string>{{"verifyToken",Field("verifyToken")},{"operationKey",Field("operationKey")},{"operationRecovery",Field("operationRecovery")}}));
        posted.StatusCode.ShouldBe(HttpStatusCode.OK);await service.Received(1).CompleteEmailChange("mailbox-proof",Arg.Any<CancellationToken>());
        posted.Headers.CacheControl!.NoStore.ShouldBeTrue();
    }
    [Fact]
    public async Task Confirmation_rejects_JSON_payload_in_favor_of_the_documented_manual_form_contract()
    {
        using var factory=new TreehammockWebApplicationFactory(TestConfiguration.ValidSettings());using var client=factory.CreateClient(new WebApplicationFactoryClientOptions{BaseAddress=new Uri("https://localhost.test")});
        using var response=await client.PostAsync("/account/adjust/email/verify",new StringContent("{\"verifyToken\":\"proof\"}",System.Text.Encoding.UTF8,"application/json"));
        response.StatusCode.ShouldBe(HttpStatusCode.UnsupportedMediaType);
    }
}
