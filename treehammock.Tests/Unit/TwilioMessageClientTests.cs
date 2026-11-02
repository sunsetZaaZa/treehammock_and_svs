using System.Net;
using Shouldly;

using treehammock.Rigging.Sidewalk;
using treehammock.Services;

namespace treehammock.Tests.Unit;

public class TwilioMessageClientTests
{
    [Fact]
    public async Task TwilioMessageClient_uses_per_request_http_basic_auth_without_static_twilio_client()
    {
        using var handler = new CapturingHandler(_ => new HttpResponseMessage(HttpStatusCode.Created)
        {
            Content = new StringContent("{\"sid\":\"SM0123456789abcdef0123456789abcdef\"}")
        });
        using var httpClient = new HttpClient(handler);
        var client = new TwilioMessageClient(new StaticHttpClientFactory(httpClient));

        ProviderDeliveryResult result = await client.SendMessage(
            "AC123",
            "secret-token",
            "+15555550199",
            "+15555550101",
            "Your Treehammock security code is 123456.");

        result.Succeeded.ShouldBeTrue();
        result.Provider.ShouldBe("twilio");
        result.ProviderMessageId.ShouldBe("SM0123456789abcdef0123456789abcdef");
        handler.Request.ShouldNotBeNull();
        handler.Request!.RequestUri!.ToString().ShouldBe("https://api.twilio.com/2010-04-01/Accounts/AC123/Messages.json");
        handler.Request.Headers.Authorization!.Scheme.ShouldBe("Basic");
        handler.RequestContent.ShouldContain("From=%2B15555550199");
        handler.RequestContent.ShouldContain("To=%2B15555550101");
        handler.RequestContent.ShouldContain("Body=Your+Treehammock+security+code+is+123456.");
    }

    [Fact]
    public async Task TwilioMessageClient_maps_rate_limit_and_provider_rejection_without_throwing()
    {
        using var rateLimitHandler = new CapturingHandler(_ => new HttpResponseMessage(HttpStatusCode.TooManyRequests));
        using var rateLimitClient = new HttpClient(rateLimitHandler);
        var rateLimited = new TwilioMessageClient(new StaticHttpClientFactory(rateLimitClient));

        ProviderDeliveryResult rateLimitResult = await rateLimited.SendMessage("AC123", "token", "+1", "+2", "body");

        rateLimitResult.Status.ShouldBe(ProviderDeliveryStatus.RateLimited);

        using var rejectedHandler = new CapturingHandler(_ => new HttpResponseMessage(HttpStatusCode.BadRequest)
        {
            Content = new StringContent("{\"code\":21614}")
        });
        using var rejectedClient = new HttpClient(rejectedHandler);
        var rejected = new TwilioMessageClient(new StaticHttpClientFactory(rejectedClient));

        ProviderDeliveryResult rejectedResult = await rejected.SendMessage("AC123", "token", "+1", "+2", "body");

        rejectedResult.Status.ShouldBe(ProviderDeliveryStatus.Rejected);
        rejectedResult.FailureCode.ShouldBe("400");
    }

    [Fact]
    public void Twilio_provider_does_not_reference_twilio_static_client_or_sdk_packages()
    {
        string projectRoot = ProjectRoot();
        string smsSource = File.ReadAllText(Path.Combine(projectRoot, "Services", "SmsSender.cs"));
        string appProject = File.ReadAllText(Path.Combine(projectRoot, "treehammock.csproj"));
        string centralPackages = File.ReadAllText(Path.Combine(projectRoot, "Directory.Packages.props"));

        smsSource.ShouldNotContain("TwilioClient.Init");
        smsSource.ShouldNotContain("MessageResource.CreateAsync");
        smsSource.ShouldNotContain("using Twilio");
        appProject.ShouldNotContain("PackageReference Include=\"Twilio\"");
        appProject.ShouldNotContain("PackageReference Include=\"Twilio.AspNet.Core\"");
        centralPackages.ShouldNotContain("PackageVersion Include=\"Twilio\"");
        centralPackages.ShouldNotContain("PackageVersion Include=\"Twilio.AspNet.Core\"");
    }

    private sealed class StaticHttpClientFactory : IHttpClientFactory
    {
        private readonly HttpClient _httpClient;

        public StaticHttpClientFactory(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }

        public HttpClient CreateClient(string name) => _httpClient;
    }

    private sealed class CapturingHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _responseFactory;

        public CapturingHandler(Func<HttpRequestMessage, HttpResponseMessage> responseFactory)
        {
            _responseFactory = responseFactory;
        }

        public HttpRequestMessage? Request { get; private set; }

        public string RequestContent { get; private set; } = string.Empty;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Request = request;
            RequestContent = request.Content is null
                ? string.Empty
                : await request.Content.ReadAsStringAsync(cancellationToken);
            return _responseFactory(request);
        }
    }

    private static string ProjectRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);

        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "treehammock.sln")))
        {
            directory = directory.Parent;
        }

        directory.ShouldNotBeNull("The test could not locate the project root containing treehammock.sln.");
        return directory.FullName;
    }
}
