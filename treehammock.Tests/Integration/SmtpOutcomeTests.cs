using treehammock.Rigging.Delivery;
using treehammock.Tests.Infrastructure;
namespace treehammock.Tests.Integration;
public sealed class Cor23ISmtpOutcomeTests
{
    public static IEnumerable<object[]> DurableKinds => new[]{"RequiredStartTls","ImplicitTls"}.SelectMany(mode=>new[]{"verify-start","verify","email","email-change-notice","delete","unlock","activation-code","factor","reset"}.Select(kind=>new object[]{mode,kind}));

    [Theory]
    [MemberData(nameof(DurableKinds))]
    public async Task Every_current_durable_kind_renders_through_required_TLS_with_its_bound_destination(string mode,string kind)
    {
        await using var server=new Cor23HSmtpServer(mode);var smtp=Cor23HSmtpTransportTests.Service(server,mode);
        string destination=kind=="email-change-notice"?"old@example.test":"new@example.test";
        Guid attempt=Guid.NewGuid();var payload=new DeliveryPayload(kind,"email",destination,"subject","proof-sentinel <script>&","https://example.test/secondary","m***@example.test");
        var result=await smtp.SendDurable(attempt,payload,TestContext.Current.CancellationToken);
        Assert.Equal(DeliverySendState.Accepted,result.State);Assert.Equal(attempt.ToString("N"),result.ReceiptId);
        var session=Assert.Single(server.Sessions);Assert.True(session.Accepted);
        using var bytes=new MemoryStream(System.Text.Encoding.UTF8.GetBytes(session.Message));var message=MimeKit.MimeMessage.Load(bytes);
        Assert.Equal(destination,Assert.Single(message.To.Mailboxes).Address);Assert.Contains("proof-sentinel",message.HtmlBody);
        if(kind=="email-change-notice")
        {
            Assert.Contains("&lt;script&gt;&amp;",message.HtmlBody.Replace(" ",""));Assert.DoesNotContain("<script>",message.HtmlBody);
        }
        Assert.All(session.Commands.Where(c=>c.Verb is "AUTH" or "MAIL" or "RCPT" or "DATA"),c=>Assert.True(c.Encrypted));
    }

    [Theory]
    [InlineData("RequiredStartTls")]
    [InlineData("ImplicitTls")]
    public async Task Email_change_primary_and_notice_keep_separate_envelope_receipts_and_recipients(string mode)
    {
        var protector=CapturingDurableDelivery.Protector();Guid account=Guid.NewGuid(),stamp=Guid.NewGuid();var expiry=NodaTime.SystemClock.Instance.GetCurrentInstant().Plus(NodaTime.Duration.FromHours(1));
        var notice=new DeliveryIntent(account,stamp,"email-notice","hash",expiry,new{originEmail="old@example.test",requestProofHash="hash"},new("email-change-notice","email","old@example.test","notice","Owner notice"));
        var main=protector.Protect(new(account,stamp,"email","hash",expiry,new{newEmailAddress="new@example.test",originEmail="old@example.test"},new("email","email","new@example.test","verify","https://example.test/proof"),notice));
        var companion=Assert.IsType<ProtectedDelivery>(main.Companion);Assert.NotEqual(main.Id,companion.Id);
        await using var server=new Cor23HSmtpServer(mode);var smtp=Cor23HSmtpTransportTests.Service(server,mode);
        var primaryResult=await smtp.SendDurable(main.Id,protector.Open(main),TestContext.Current.CancellationToken);
        var noticeResult=await smtp.SendDurable(companion.Id,protector.Open(companion),TestContext.Current.CancellationToken);
        Assert.Equal(DeliverySendState.Accepted,primaryResult.State);Assert.Equal(DeliverySendState.Accepted,noticeResult.State);
        Assert.Equal(main.Id.ToString("N"),primaryResult.ReceiptId);Assert.Equal(companion.Id.ToString("N"),noticeResult.ReceiptId);
        var recipients=server.Sessions.Select(s=>
        {
            using var bytes=new MemoryStream(System.Text.Encoding.UTF8.GetBytes(s.Message));return Assert.Single(MimeKit.MimeMessage.Load(bytes).To.Mailboxes).Address;
        }).ToArray();
        Assert.Equal(new[]{"new@example.test","old@example.test"},recipients);
    }

    [Theory]
    [InlineData("unknown-kind","value")]
    [InlineData("email-change-notice","")]
    [InlineData("email-change-notice"," ")]
    public async Task Unsupported_or_corrupt_payload_does_not_start_SMTP_submission(string kind,string value)
    {
        await using var server=new Cor23HSmtpServer("RequiredStartTls");var smtp=Cor23HSmtpTransportTests.Service(server,"RequiredStartTls");
        await Assert.ThrowsAsync<InvalidOperationException>(async()=>await smtp.SendDurable(Guid.NewGuid(),new(kind,"email","old@example.test","notice",value),TestContext.Current.CancellationToken));
        Assert.Empty(server.Sessions);
    }

    [Theory]
    [InlineData("RequiredStartTls","accept-drop",DeliverySendState.Unknown,false)]
    [InlineData("ImplicitTls","accept-drop",DeliverySendState.Unknown,false)]
    [InlineData("RequiredStartTls","reject-data",DeliverySendState.Rejected,false)]
    [InlineData("ImplicitTls","reject-data",DeliverySendState.Rejected,false)]
    [InlineData("RequiredStartTls","temporary-data",DeliverySendState.NotSubmitted,true)]
    [InlineData("ImplicitTls","temporary-data",DeliverySendState.NotSubmitted,true)]
    [InlineData("RequiredStartTls","disconnect-after-accept",DeliverySendState.Accepted,false)]
    [InlineData("ImplicitTls","disconnect-after-accept",DeliverySendState.Accepted,false)]
    public async Task Real_TLS_relay_distinguishes_DATA_acceptance_lost_ACK_definite_rejection_and_disconnect(string mode,string fault,DeliverySendState expected,bool retry)
    {
        await using var server=new Cor23HSmtpServer(mode,fault);var smtp=Cor23HSmtpTransportTests.Service(server,mode);
        Guid attempt=Guid.NewGuid();var result=await smtp.SendDurable(attempt,new("verify","email","recipient@example.test","verify","proof-sentinel"),TestContext.Current.CancellationToken);
        Assert.Equal(expected,result.State);Assert.Equal(retry,result.CanRetry);Assert.Equal("smtp",result.Provider);
        var session=Assert.Single(server.Sessions);Assert.Contains("proof-sentinel",session.Message);
        Assert.All(session.Commands.Where(c=>c.Verb is "AUTH" or "MAIL" or "RCPT" or "DATA"),c=>Assert.True(c.Encrypted));
        Assert.Equal(fault is "accept-drop" or "disconnect-after-accept",session.Accepted);
        if(expected==DeliverySendState.Accepted)Assert.Equal(attempt.ToString("N"),result.ReceiptId);
    }
    [Theory]
    [InlineData("RequiredStartTls")] [InlineData("ImplicitTls")]
    public async Task Legacy_mail_surface_preserves_unknown_as_null_after_actual_DATA_acceptance(string mode)
    {
        await using var server=new Cor23HSmtpServer(mode,"accept-drop");
        Assert.Null(await Cor23HSmtpTransportTests.Service(server,mode).VerificationLetter("recipient@example.test","verify","proof-sentinel"));
        Assert.True(Assert.Single(server.Sessions).Accepted);
    }
}
