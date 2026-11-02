using Microsoft.Extensions.Options;
using treehammock.Rigging.Config;
using treehammock.Rigging.Delivery;
using treehammock.Services;
using treehammock.Tests.Infrastructure;
using treehammock.Tests.Unit;
namespace treehammock.Tests.Integration;
public sealed class Cor23KSmtpHealthTests
{
    [Theory][InlineData("RequiredStartTls")][InlineData("ImplicitTls")]
    public async Task Real_recipient_rejection_is_neutral_and_the_next_valid_recipient_remains_usable(string mode)
    {
        await using var server=new Cor23HSmtpServer(mode,"reject-recipient");var settings=Cor23HSmtpTransportTests.Settings(server,mode);var health=new Cor23KProviderHealthTests.Health();
        var mail=new SMTPService(Options.Create(settings),Options.Create(new EmailTemplateSettings()),new Cor23HSmtpTransportTests.Logs(),new(settings,"Testing"),server.Clients(),health:health);
        Assert.False(await mail.Send("bad@example.test","subject","body"));Assert.True(await mail.Send("good@example.test","subject","body"));
        Assert.Equal(new[]{ProviderHealthEvidence.Neutral,ProviderHealthEvidence.Healthy},health.Evidence);Assert.Equal(2,server.Sessions.Count);
    }
    [Theory][InlineData("reject-auth")][InlineData("reject-starttls")]
    public async Task Credential_or_TLS_configuration_failure_does_not_count_as_a_provider_outage(string fault)
    {
        await using var server=new Cor23HSmtpServer("RequiredStartTls",fault);var settings=Cor23HSmtpTransportTests.Settings(server,"RequiredStartTls");var health=new Cor23KProviderHealthTests.Health();
        var mail=new SMTPService(Options.Create(settings),Options.Create(new EmailTemplateSettings()),new Cor23HSmtpTransportTests.Logs(),new(settings,"Testing"),server.Clients(),health:health);
        Assert.False(await mail.Send("good@example.test","subject","body"));Assert.Equal(ProviderHealthEvidence.Neutral,Assert.Single(health.Evidence));
    }
    [Fact]
    public async Task An_open_SMTP_route_returns_non_submission_without_a_socket()
    {
        await using var server=new Cor23HSmtpServer("RequiredStartTls");var settings=Cor23HSmtpTransportTests.Settings(server,"RequiredStartTls");var health=new Cor23KProviderHealthTests.Health{Blocked=DeliveryRoute.Smtp};
        var mail=new SMTPService(Options.Create(settings),Options.Create(new EmailTemplateSettings()),new Cor23HSmtpTransportTests.Logs(),new(settings,"Testing"),server.Clients(),health:health);
        var result=await mail.SendDurable(Guid.NewGuid(),new("verify","email","good@example.test","verify","proof"),CancellationToken.None);
        Assert.Equal(DeliverySendState.NotSubmitted,result.State);Assert.True(result.CanRetry);Assert.Empty(server.Sessions);
    }
}
