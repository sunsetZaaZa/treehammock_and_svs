using Shouldly;
using System.Text.RegularExpressions;

namespace treehammock.Tests.Unit;

public class ActivationApiContractTests
{
    [Fact]
    public void Activations_controller_is_api_controller_not_mvc_view_shell()
    {
        string source = File.ReadAllText(ProjectFile("Controllers", "ActivationsController.cs"));

        source.ShouldContain("class ActivationsController : ControllerBase");
        source.ShouldContain("[ApiController]");
        source.ShouldContain("[Route(\"activations\")]");
        source.ShouldContain("[HttpPost(\"place\")]");
        source.ShouldContain("[HttpPost(\"verify\")]");
        source.ShouldContain("[HttpPost(\"disable\")]");
        source.ShouldNotContain("return View();");
    }

    [Fact]
    public void Activation_creation_request_no_longer_accepts_client_supplied_code()
    {
        string source = File.ReadAllText(ProjectFile("Models", "Activation", "ActivationCreation.cs"));

        source.ShouldNotContain("required string code");
        source.ShouldNotContain("string code");
    }

    [Fact]
    public void Activation_sql_returns_explicit_result_codes_for_stale_stamp_expired_and_code_mismatch()
    {
        string sql = File.ReadAllText(ProjectFile("Rigging", "Database", "Baseline", "000_treehammock_canonical_database.sql"));

        sql.ShouldContain("returns table(result boolean, code text, status smallint)");
        sql.ShouldContain("returns table(\n    result boolean,\n    code text,");
        sql.ShouldContain("ACCOUNT_SECURITY_STAMP_MISMATCH");
        sql.ShouldContain("ACTIVATION_EXPIRED");
        sql.ShouldContain("ACTIVATION_CODE_MISMATCH");
        sql.ShouldContain("ACTIVATION_APPROVAL_MISMATCH");
    }

    [Fact]
    public void Activations_controller_maps_stale_stamp_to_401_and_expired_activation_to_410()
    {
        string source = File.ReadAllText(ProjectFile("Controllers", "ActivationsController.cs"));

        source.ShouldContain("ActivationService.SecurityStampMismatchCode => StatusCodes.Status401Unauthorized");
        source.ShouldContain("ActivationService.ExpiredCode => StatusCodes.Status410Gone");
        source.ShouldContain("ActivationService.CodeMismatchCode");
        source.ShouldContain("ActivationService.PendingCode or AbuseReasonCodes.DeliveryThrottleExceeded or AbuseReasonCodes.FailureCooldownActive => StatusCodes.Status429TooManyRequests");
        source.ShouldContain("AbuseReasonCodes.CounterStoreUnavailable or AbuseReasonCodes.CounterStoreTimeout => StatusCodes.Status503ServiceUnavailable");
        source.ShouldContain("StatusCodes.Status429TooManyRequests");
        source.ShouldContain("StatusCodes.Status503ServiceUnavailable");
        source.ShouldContain("StatusCodes.Status428PreconditionRequired");
    }

    [Fact]
    public void Activation_sql_stores_backend_supplied_code_instead_of_generating_one()
    {
        string sql = File.ReadAllText(ProjectFile("Rigging", "Database", "Baseline", "000_treehammock_canonical_database.sql"));
        int start = sql.IndexOf("create or replace function place_activation(", StringComparison.Ordinal);
        int end = sql.IndexOf("create or replace function cancel_activation_request(", StringComparison.Ordinal);
        string placeActivation = sql[start..end];

        placeActivation.ShouldContain("p_code text");
        placeActivation.ShouldContain("ACTIVATION_TRUSTED_GRANT_REQUIRED");
        placeActivation.ShouldNotContain("insert into activations");
        placeActivation.ShouldNotContain("gen_random_uuid()::text");
    }


    [Fact]
    public void Activation_creation_validates_term_and_recycle_before_service_sql_contracts()
    {
        string controller = File.ReadAllText(ProjectFile("Controllers", "ActivationsController.cs"));
        string service = File.ReadAllText(ProjectFile("Services", "ActivationService.cs"));
        string sql = File.ReadAllText(ProjectFile("Rigging", "Database", "Baseline", "000_treehammock_canonical_database.sql"));

        controller.ShouldContain("Enum.IsDefined(typeof(DayDuration), payload.term)");
        controller.ShouldContain("Enum.IsDefined(typeof(DurationRepeat), payload.recycle)");
        controller.ShouldContain("ActivationService.InvalidTermCode");
        controller.ShouldContain("ActivationService.InvalidRecycleCode");

        service.ShouldContain("public const string InvalidTermCode = \"ACTIVATION_INVALID_TERM\"");
        service.ShouldContain("public const string InvalidRecycleCode = \"ACTIVATION_INVALID_RECYCLE\"");
        service.ShouldContain("IsSupportedActivationTerm(request.term)");
        service.ShouldContain("IsSupportedActivationRecycle(request.recycle)");
        service.ShouldNotContain("Duration.FromDays(31)");
        service.ShouldContain("HashCode(code)");

        string issuer = SqlFunction(sql, "cor19_issue_grant");
        issuer.ShouldContain("p_term is null or p_term not in (1,2,3,6,7,8,9,10,11)");
        issuer.ShouldContain("p_cadence is null or p_cadence not in (0,1)");
        issuer.ShouldContain("ENTITLEMENT_INVALID_APPROVAL");
        issuer.ShouldContain("cor19_is_issuer(current_user::name)");
        issuer.ShouldContain("perform cor02_lock_account_authority(p_account,'activation')");
        string placement = SqlFunction(sql, "cor19_stage_activation");
        placement.ShouldContain("cor19_grant_live(p_grant,p_account,p_stamp,p_version)");
        placement.ShouldContain("g.tier=p_tier and g.term=p_term and g.cadence=p_cadence");
        placement.ShouldContain("ACTIVATION_APPROVAL_MISMATCH");
        // Native Cor25ActivationApprovalBoundaryTests exercises all supported/retired boundaries and exact placement approval.
    }


    [Fact]
    public void Activation_controller_rejects_unbounded_email_and_code_inputs()
    {
        string controller = File.ReadAllText(ProjectFile("Controllers", "ActivationsController.cs"));
        string creationModel = File.ReadAllText(ProjectFile("Models", "Activation", "ActivationCreation.cs"));
        string detailsModel = File.ReadAllText(ProjectFile("Models", "Activation", "ActivationDetails.cs"));
        string unsubscribeModel = File.ReadAllText(ProjectFile("Models", "Activation", "ActivationUnSubscribe.cs"));

        creationModel.ShouldContain("MaxEmailAddressLength = 1024");
        detailsModel.ShouldContain("MaxEmailAddressLength = 1024");
        detailsModel.ShouldContain("MaxCodeLength = 128");
        unsubscribeModel.ShouldContain("MaxEmailAddressLength = 1024");

        controller.ShouldContain("payload.emailAddress = payload.emailAddress?.Trim() ?? string.Empty;");
        controller.ShouldContain("payload.code = payload.code?.Trim() ?? string.Empty;");
        controller.ShouldContain("emailAddress must be no longer than");
        controller.ShouldContain("code must be no longer than");
    }

    // Supplemental source contract only; actual SQL authority is tested by the owned native suites.
    private static string SqlFunction(string sql, string name)
    {
        MatchCollection declarations = Regex.Matches(sql,
            @"(?im)^\s*create\s+or\s+replace\s+function\s+" + Regex.Escape(name) + @"\s*\(");
        declarations.Count.ShouldBe(1, "The current canonical routine must have one effective definition: " + name);
        int start = declarations[0].Index;
        Match body = Regex.Match(sql[start..], @"(?i)\bas\s+(\$\w*\$)");
        body.Success.ShouldBeTrue();
        string delimiter = body.Groups[1].Value;
        int bodyStart = start + body.Index + body.Length;
        int end = sql.IndexOf(delimiter, bodyStart, StringComparison.Ordinal);
        end.ShouldBeGreaterThanOrEqualTo(bodyStart);
        return Regex.Replace(sql[start..(end + delimiter.Length)], @"\s+", " ");
    }

    private static string ProjectFile(params string[] relativePath)
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);

        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "treehammock.sln")))
        {
            directory = directory.Parent;
        }

        directory.ShouldNotBeNull("The test could not locate the project root containing treehammock.sln.");
        return Path.Combine(new[] { directory.FullName }.Concat(relativePath).ToArray());
    }
}
