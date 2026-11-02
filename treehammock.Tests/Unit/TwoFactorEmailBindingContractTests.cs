using Microsoft.AspNetCore.Http;
using NodaTime;
using NSubstitute;
using Shouldly;

using treehammock.Models.Account;
using treehammock.Models.Api;
using treehammock.Models.Authentication;
using treehammock.Repos;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;
using treehammock.Tests.Infrastructure;

namespace treehammock.Tests.Unit;

public class TwoFactorEmailBindingContractTests
{
    [Fact]
    public void Begin_twofactor_setup_binds_email_destination_to_account_email()
    {
        string sql = File.ReadAllText(ProjectFile("Rigging", "Database", "Baseline", "000_treehammock_canonical_database.sql"));
        string function = sql[sql.IndexOf("create or replace function cor16_begin_twofactor_setup", StringComparison.Ordinal)..];

        function.ShouldContain("lower(p_emailAddress) is distinct from lower(a.email_address)");
        function.ShouldContain("case when p_method=1 then lower(a.email_address) end");
        function.ShouldContain("TWO_FACTOR_SETUP_INVALID_DESTINATION");

        function.ShouldNotContain("normalized_email text := nullif(lower(trim(p_emailAddress)), '')");
    }

    [Fact]
    public void Get_twofactor_details_returns_current_account_email_for_email_factor()
    {
        string sql = File.ReadAllText(ProjectFile("Rigging", "Database", "Baseline", "000_treehammock_canonical_database.sql"));
        string function = Slice(sql, "create or replace function get_twofactor_details", "create or replace function begin_twofactor_setup");

        function.ShouldContain("join accounts a on a.account_id = t.account_id");
        function.ShouldContain("case when t.method = 1 then a.email_address else t.email_address end as email_address");
    }

    [Fact]
    public void Complete_account_email_change_turns_off_verified_email_factor()
    {
        string sql = File.ReadAllText(ProjectFile("Rigging", "Database", "Baseline", "000_treehammock_canonical_database.sql"));
        string function = Slice(sql, "create or replace function complete_account_email_change", "create or replace function purge_expired_account_email_change_requests");

        function.ShouldContain("delete from two_factor_authentications");
        function.ShouldContain("method=1 and verified=true");
        function.ShouldContain("or not verified");
        function.ShouldContain("two_factor_auth_method=remaining_summary.selected_method");
        function.ShouldContain("two_auth_usage=remaining_summary.usage_count");
    }

    [Fact]
    public async Task Setup_email_two_factor_uses_account_email_for_persistence_and_delivery()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateTwoFactorController();
        var session = harness.SetAuthenticatedSession();
        var request = new SetupLayeredAuthenticateMethodRequest(TwoFactorAuthMethod.EMAIL, "Reader@Example.Test", null, true);
        harness.AccountRepo.ViewAccount(session.accountId, session.accountSecurityStamp, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<AccountViewResult?>(AccountEmailView("reader@example.test")));
        harness.AccountRepo.BeginTwoFactorSetup(
                Arg.Is<Guid>(value => value == session.accountId),
                Arg.Is<Guid>(value => value == session.accountSecurityStamp),
                Arg.Is<TwoFactorAuthMethod>(value => value == TwoFactorAuthMethod.EMAIL),
                Arg.Any<string?>()!,
                Arg.Any<Instant>(),
                Arg.Any<Instant>(),
                Arg.Is<string?>(value => value == "reader@example.test")!,
                Arg.Is<string?>(value => value == null)!,
                Arg.Is<string?>(value => value == null)!,
                Arg.Is<string?>(value => value == null)!,
                Arg.Is<bool>(value => value), cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<TwoFactorSetupCommandResult?>(new TwoFactorSetupCommandResult(true, "TWO_FACTOR_SETUP_PENDING", 0, SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(5)))));

        var actionResult = await controller.SetupTwoFactorMethod(request);

        ApiResponse<SetupLayeredAuthenticateMethodResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status202Accepted);
        envelope.success.ShouldBeTrue();
        await harness.AccountRepo.Received(1).ViewAccount(session.accountId, session.accountSecurityStamp, cancellationToken: Arg.Any<CancellationToken>());
        var candidate=harness.Delivery.Intents.Single();candidate.AccountId.ShouldBe(session.accountId);candidate.AccountStamp.ShouldBe(session.accountSecurityStamp);candidate.Payload.Destination.ShouldBe("reader@example.test");
    }
    private static AccountViewResult AccountEmailView(string emailAddress)
    {
        return new AccountViewResult(true, "ACCOUNT_VIEW_SUCCEEDED", new AccountProfile
        {
            emailAddress = emailAddress,
            username = "reader",
            createdOn = SystemClock.Instance.GetCurrentInstant(),
            verifyStatus = VerificationStatus.SUCCESSFUL,
            country = Country.NONE,
            features = FeatureSet.basic,
            twoFactorEnabled = false
        });
    }

    private static string Slice(string text, string startMarker, string endMarker)
    {
        int start = text.IndexOf(startMarker, StringComparison.Ordinal);
        start.ShouldBeGreaterThanOrEqualTo(0);
        int end = text.IndexOf(endMarker, start + startMarker.Length, StringComparison.Ordinal);
        end.ShouldBeGreaterThan(start);
        return text[start..end];
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

    private static string ProjectFile(params string[] relativePathParts)
    {
        return Path.Combine(new[] { ProjectRoot() }.Concat(relativePathParts).ToArray());
    }
}
