using System.Net;
using System.Net.Http.Headers;
using NodaTime;
using NSubstitute;
using Shouldly;
using treehammock.Entities;
using treehammock.Rigging.Security;
using treehammock.RiggingSupport.Enum;
using treehammock.Tests.Infrastructure;

namespace treehammock.Tests.Integration;

public sealed class Cor23AERegistrationVerificationHttpTests
{
    [Fact]
    public async Task Independent_observer_proves_only_intended_account_verified()
    {
        await using var fixture = new VerificationFixture();
        using var response = await fixture.Verify(fixture.Token);
        string body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        RegistrationVerificationAssertions.AssertSuccessPage(response, body, Template("success"));
        fixture.Observe(fixture.AccountId).ShouldBe(VerificationStatus.SUCCESSFUL);
        fixture.Observe(fixture.OtherAccountId).ShouldBe(VerificationStatus.SENT);
        fixture.Completions.ShouldBe(1);
    }

    [Fact]
    public async Task Invalid_token_returns_failure_html_without_committing()
    {
        await using var fixture = new VerificationFixture();
        using var response = await fixture.Verify(AccountVerificationTokenUtility.GenerateToken());
        await AssertRejected(response, "failure");
        fixture.AssertUncommitted(0);
    }

    [Fact]
    public async Task Expired_token_returns_expired_html_without_committing()
    {
        await using var fixture = new VerificationFixture(expired: true);
        using var response = await fixture.Verify(fixture.Token);
        await AssertRejected(response, "expired");
        fixture.Observe(fixture.AccountId).ShouldBe(VerificationStatus.EXPIRED);
        fixture.Observe(fixture.OtherAccountId).ShouldBe(VerificationStatus.SENT);
        fixture.Completions.ShouldBe(0);
    }

    [Fact]
    public async Task Http_200_error_page_cannot_satisfy_verification_success()
    {
        await using var fixture = new VerificationFixture(completion: false);
        using var response = await fixture.Verify(fixture.Token);
        await AssertRejected(response, "failure");
        fixture.AssertUncommitted(1);
    }

    [Fact]
    public async Task Unavailable_completion_returns_failure_html_without_committing()
    {
        await using var fixture = new VerificationFixture(completion: null);
        using var response = await fixture.Verify(fixture.Token);
        await AssertRejected(response, "failure");
        fixture.AssertUncommitted(1);
    }

    [Fact]
    public async Task Unavailable_lookup_returns_failure_html_without_committing()
    {
        await using var fixture = new VerificationFixture(lookupUnavailable: true);
        using var response = await fixture.Verify(fixture.Token);
        await AssertRejected(response, "failure");
        fixture.AssertUncommitted(0);
    }

    [Fact]
    public async Task Already_verified_returns_its_template_without_another_commit()
    {
        await using var fixture = new VerificationFixture();
        using (var first = await fixture.Verify(fixture.Token))
            RegistrationVerificationAssertions.AssertSuccessPage(first,
                await first.Content.ReadAsStringAsync(TestContext.Current.CancellationToken), Template("success"));
        using var response = await fixture.Verify(fixture.Token);
        await AssertRejected(response, "already-verified");
        fixture.Observe(fixture.AccountId).ShouldBe(VerificationStatus.SUCCESSFUL);
        fixture.Observe(fixture.OtherAccountId).ShouldBe(VerificationStatus.SENT);
        fixture.Completions.ShouldBe(1);
    }

    [Fact]
    public void Successful_marker_inside_failure_html_is_insufficient()
    {
        using var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("<h1>Account verified</h1>" + Template("failure")) };
        response.Content.Headers.ContentType = new MediaTypeHeaderValue("text/html");
        Should.Throw<ShouldAssertException>(() => RegistrationVerificationAssertions.AssertSuccessPage(response,
            "<h1>Account verified</h1>" + Template("failure"), Template("success")));
    }

    [Fact]
    public void Successful_content_requires_html_media_type()
    {
        using var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(Template("success")) };
        Should.Throw<ShouldAssertException>(() => RegistrationVerificationAssertions.AssertSuccessPage(response, Template("success"), Template("success")));
    }

    [Fact]
    public void Successful_content_requires_a_content_type_header()
    {
        using var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(Template("success")) };
        response.Content.Headers.ContentType = null;
        Should.Throw<ShouldAssertException>(() => RegistrationVerificationAssertions.AssertSuccessPage(response, Template("success"), Template("success")));
    }

    private static string Template(string name) => RegistrationVerificationAssertions.LoadTemplate(name);

    private static async Task AssertRejected(HttpResponseMessage response, string outcome)
    {
        string body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        (response.Content.Headers.ContentType?.MediaType).ShouldBe("text/html");
        body.ShouldBe(Template(outcome));
        Should.Throw<ShouldAssertException>(() => RegistrationVerificationAssertions.AssertSuccessPage(response, body, Template("success")));
    }

    // Actual Program/MVC with an isolated in-memory repository authority, not a SQL qualification.
    // Each read returns a detached record; only the completion callback can commit success.
    private sealed class VerificationFixture : IAsyncDisposable
    {
        internal readonly Guid AccountId = Guid.NewGuid(), OtherAccountId = Guid.NewGuid();
        internal readonly string Token = AccountVerificationTokenUtility.GenerateToken();
        private readonly Dictionary<Guid, VerificationStatus> _state = new();
        private readonly TreehammockWebApplicationFactory _factory;
        private readonly HttpClient _client;
        internal int Completions;

        internal VerificationFixture(bool? completion = true, bool expired = false, bool lookupUnavailable = false)
        {
            _state[AccountId] = VerificationStatus.SENT;
            _state[OtherAccountId] = VerificationStatus.SENT;
            var links = new Cor23GLinkFixture();
            string hash = AccountVerificationTokenUtility.HashToken(Token);
            Instant sent = SystemClock.Instance.GetCurrentInstant() - Duration.FromHours(expired ? 2 : 0);
            Guid version = Guid.NewGuid(), stamp = Guid.NewGuid();
            links.Repo.VerifyAccountForUse(Arg.Any<string>(), Arg.Any<CancellationToken>()).Returns(call =>
                Task.FromResult<AccountVerification?>(!lookupUnavailable && call.ArgAt<string>(0) == Token
                    ? new AccountVerification(AccountId, hash, Observe(AccountId), sent, Period.FromHours(1))
                        { proofVersion = version, accountSecurityStamp = stamp } : null));
            links.Repo.AccountPassedVerification(Arg.Any<AccountVerification>(), Arg.Any<CancellationToken>()).Returns(call =>
            {
                AccountVerification record = call.ArgAt<AccountVerification>(0);
                record.accountId.ShouldBe(AccountId);
                record.verifyKey.ShouldBe(hash);
                record.proofVersion.ShouldBe(version);
                record.accountSecurityStamp.ShouldBe(stamp);
                Completions++;
                if (completion == true) _state[AccountId] = VerificationStatus.SUCCESSFUL;
                return Task.FromResult(completion);
            });
            links.Repo.AccountVerificationExpired(Arg.Any<AccountVerification>(), Arg.Any<CancellationToken>()).Returns(call =>
            {
                call.ArgAt<AccountVerification>(0).accountId.ShouldBe(AccountId);
                _state[AccountId] = VerificationStatus.EXPIRED;
                return Task.FromResult<bool?>(true);
            });
            var settings = Cor23EAuthorityFixture.Settings();
            settings["AbuseControlSettings:Enabled"] = "false";
            _factory = new TreehammockWebApplicationFactory(settings, services => Cor23GPublicHttpFixture.Configure(services, links));
            try { _client = _factory.CreateClient(); }
            catch { _factory.Dispose(); throw; }
        }

        internal VerificationStatus Observe(Guid id) => _state[id];
        internal Task<HttpResponseMessage> Verify(string token) => _client.GetAsync(
            "/account/verifyaccount?payload=" + Uri.EscapeDataString(token), TestContext.Current.CancellationToken);
        internal void AssertUncommitted(int attempts)
        {
            Observe(AccountId).ShouldBe(VerificationStatus.SENT);
            Observe(OtherAccountId).ShouldBe(VerificationStatus.SENT);
            Completions.ShouldBe(attempts);
        }
        public async ValueTask DisposeAsync()
        {
            _client.Dispose();
            await _factory.DisposeAsync();
        }
    }
}
