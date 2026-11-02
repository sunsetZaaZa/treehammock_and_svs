using Shouldly;
using System.Text.RegularExpressions;

namespace treehammock.Tests.Unit;

public class AccountRecoveryApiContractTests
{
    [Fact]
    public void Account_unlock_controller_exposes_start_and_verify_token_endpoints()
    {
        string source = File.ReadAllText(ProjectFile("Controllers", "AccountRecoveryController.cs"));

        source.ShouldContain("class AccountRecoveryController : ControllerBase");
        source.ShouldContain("[ApiController]");
        source.ShouldContain("[AllowAnonymous]");
        source.ShouldContain("[Route(\"account/unlock\")]");
        source.ShouldContain("[HttpPost(\"start\")]");
        source.ShouldContain("[HttpPost(\"verify\")]");
        source.ShouldNotContain("[Authenticate]");
        source.ShouldNotContain("AccountRecovery_Topic");
        source.ShouldNotContain("AccountRecovery_Type");
    }


    [Fact]
    public void Account_unlock_verify_endpoint_advertises_abuse_replay_failure_status_codes()
    {
        string source = File.ReadAllText(ProjectFile("Controllers", "AccountRecoveryController.cs"));

        source.ShouldContain("StatusCodes.Status429TooManyRequests");
        source.ShouldContain("StatusCodes.Status503ServiceUnavailable");
        source.ShouldContain("AbuseReasonCodes.AccountUnlockVerifyAttemptsExceeded");
        source.ShouldContain("AbuseReasonCodes.CounterStoreUnavailable");
    }

    [Fact]
    public void Account_unlock_sql_only_starts_for_currently_locked_accounts_and_clears_lockout_on_verify()
    {
        string sql = File.ReadAllText(ProjectFile("Rigging", "Database", "Baseline", "000_treehammock_canonical_database.sql"));

        sql.ShouldContain("create or replace function lookup_locked_recovery_account");
        sql.ShouldContain("create or replace function start_unlock_account");
        sql.ShouldContain("create or replace function cancel_unlock_account");
        sql.ShouldContain("create or replace function verify_unlock_account");
        sql.ShouldContain("unlock_when is not null");
        sql.ShouldContain("unlock_when > p_now");
        sql.ShouldContain("phone_number text");
        sql.ShouldContain("phone_country_code text");
        sql.ShouldContain("t.method = 2");
        sql.ShouldContain("t.verified = true");
        sql.ShouldContain("lockout_security_stamp uuid not null");
        sql.ShouldContain("lockout_unlock_when timestamp with time zone not null");
        sql.ShouldContain("p_accountSecurityStamp uuid");
        sql.ShouldContain("p_lockoutUnlockWhen timestamp with time zone");
        sql.ShouldContain("v_security_stamp is distinct from p_accountSecurityStamp");
        sql.ShouldContain("v_unlock_when is distinct from p_lockoutUnlockWhen");
        sql.ShouldContain("v_account_security_stamp is distinct from v_recovery.lockout_security_stamp");
        sql.ShouldContain("v_account_unlock_when is distinct from v_recovery.lockout_unlock_when");
        sql.ShouldContain("set status = 14");
        sql.ShouldContain("set unlock_when = null,");
        sql.ShouldContain("login_failures = 0");
        sql.ShouldContain("if v_recovery.status = 7 then");
        sql.ShouldContain("if v_recovery.status = 4 then");
        sql.ShouldContain("p_expiration timestamp with time zone");
        sql.ShouldContain("p_method smallint");
        sql.ShouldContain("if p_method not in (1, 2) then");
        sql.ShouldContain("return query select 10::smallint");
        sql.ShouldContain("p_method,");
        sql.ShouldContain("method = excluded.method");
        sql.ShouldNotContain("create or replace function start_recover_account");
        sql.ShouldNotContain("p_createdOn + interval '1 day'");
    }


    [Fact]
    public void Account_unlock_start_request_accepts_identifier_and_delivery_method_and_stale_recovery_enums_are_removed()
    {
        string model = File.ReadAllText(ProjectFile("Models", "Recovery", "AccountRecovery.cs"));

        model.ShouldContain("public AccountRecoveryRequest(string identifier)");
        model.ShouldContain("public AccountRecoveryRequest(string identifier, AccountUnlockDeliveryMethod deliveryMethod)");
        model.ShouldContain("public required string identifier { get; set; }");
        model.ShouldContain("public AccountUnlockDeliveryMethod deliveryMethod { get; set; } = AccountUnlockDeliveryMethod.EMAIL;");
        model.ShouldNotContain("currentTime");
        model.ShouldNotContain("LocalDateTime");
        File.Exists(ProjectFile("RiggingSupport", "Enum", "AccountRecovery.cs")).ShouldBeFalse();
        File.Exists(ProjectFile("Entities", "AccountRecovery.cs")).ShouldBeFalse();
    }

    [Fact]
    public void Account_unlock_delivery_uses_templated_email_and_sms_sender_contracts()
    {
        string service = File.ReadAllText(ProjectFile("Services", "AccountRecoveryService.cs"));
        string smtp = File.ReadAllText(ProjectFile("Services", "SMTPService.cs"));
        string subjects = File.ReadAllText(ProjectFile("Rigging", "Config", "EmailSubjectSettings.cs"));
        string templates = File.ReadAllText(ProjectFile("Rigging", "Config", "EmailTemplateSettings.cs"));

        int start = service.IndexOf("public async Task<AccountRecoveryStartResult> StartRecovery", StringComparison.Ordinal);
        int end = service.IndexOf("public async Task<AccountRecoveryVerifyResult> VerifyRecovery", start, StringComparison.Ordinal);
        start.ShouldBeGreaterThanOrEqualTo(0); end.ShouldBeGreaterThan(start);
        string producer = Regex.Replace(service[start..end], @"\s+", " ");
        producer.ShouldContain("_delivery.AdmitAsync(AbuseFeature.AccountUnlock,channel,lookup.AccountId.Value,destination,cancellationToken)");
        producer.ShouldContain("_delivery.ExistingAsync(lookup.AccountId.Value,lookup.AccountSecurityStamp.Value,\"unlock\",cancellationToken)");
        producer.ShouldContain("SecretHashUtility.HashToken(token)");
        producer.ShouldContain("createdOn.Plus(Duration.FromHours(1))");
        producer.ShouldContain("method=(short)request.deliveryMethod");
        producer.ShouldContain("lockoutUnlockWhen=lookup.UnlockWhen.Value,lockoutAttemptVersion=lookup.LockoutAttemptVersion.Value");
        producer.ShouldContain("new(\"unlock\",channel,destination,_emailSubjectSettings.AccountUnlock,token)");
        producer.IndexOf("_delivery.AdmitAsync", StringComparison.Ordinal).ShouldBeLessThan(producer.IndexOf("GenerateRecoveryToken()", StringComparison.Ordinal));
        producer.IndexOf("GenerateRecoveryToken()", StringComparison.Ordinal).ShouldBeLessThan(producer.IndexOf("_delivery.EnqueueAsync", StringComparison.Ordinal));
        producer.ShouldNotContain("BeginUnlock(");
        producer.ShouldNotContain("AccountUnlockLetter(");
        producer.ShouldNotContain("SendCode(");
        service.ShouldContain("AccountUnlockDeliveryMethod.EMAIL");
        service.ShouldContain("AccountUnlockDeliveryMethod.SMS");
        service.ShouldNotContain("BuildUnlockEmailBody");

        string adapter = File.ReadAllText(ProjectFile("Services", "DeliveryProviderAdapter.cs"));
        adapter.ShouldContain("if(p.Channel==\"sms\")");
        adapter.ShouldContain("sms.SendDurable(jobId,p,token)");
        adapter.ShouldContain("smtp.SendDurable(jobId,p,token)");
        string worker = File.ReadAllText(ProjectFile("Services", "DeliveryOutboxWorker.cs"));
        int persistStart = worker.IndexOf("private async Task<bool> PersistAsync", StringComparison.Ordinal);
        int persistEnd = worker.IndexOf("protected override async Task ExecuteAsync", persistStart, StringComparison.Ordinal);
        persistStart.ShouldBeGreaterThanOrEqualTo(0); persistEnd.ShouldBeGreaterThan(persistStart);
        string publication = worker[persistStart..persistEnd];
        publication.ShouldContain("if(!await repo.RecordAsync(job,result,persist.Token))return true;");
        publication.ShouldContain("if(result.State==DeliverySendState.Accepted)await repo.PublishAsync(job.Delivery.Id,persist.Token);");
        smtp.ShouldContain("\"unlock\"=>ApplySequenceTemplate(_accountUnlockTemplate,p.Value)");
        // Native service inline-data and Cor12DeliveryOutboxTests remain the behavioral publication oracle.
        smtp.ShouldContain("AccountUnlockLetter");
        subjects.ShouldContain("AccountUnlock");
        templates.ShouldContain("AccountUnlock");
        File.Exists(ProjectFile("email_templates", "AccountUnlock.html")).ShouldBeTrue();
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
