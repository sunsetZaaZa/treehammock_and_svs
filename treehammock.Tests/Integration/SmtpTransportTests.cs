using System.Security.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using treehammock.Rigging.Config;
using treehammock.Rigging.Delivery;
using treehammock.Services;
using treehammock.Tests.Infrastructure;

namespace treehammock.Tests.Integration;

public sealed class Cor23HSmtpTransportTests
{
    internal sealed class Logs : ILogger<SMTPService>
    {
        internal readonly List<string> Messages=new();
        public IDisposable? BeginScope<TState>(TState state) where TState:notnull=>null;
        public bool IsEnabled(LogLevel level)=>true;
        public void Log<TState>(LogLevel level,EventId id,TState state,Exception? exception,Func<TState,Exception?,string> formatter)
        {Assert.Null(exception);Messages.Add(formatter(state,exception));}
    }
    internal static SMTPSettings Settings(Cor23HSmtpServer server,string mode)=>new() {SMTPQualifiedDomain="127.0.0.1",SMTPPort=server.Port,SMTPUsername="fixture-user-secret",SMTPPassword="fixture-password-secret",NoReplyEmailAddress="sender@example.test",TransportMode=Enum.Parse<SmtpTransportMode>(mode),AllowIsolatedPlaintext=mode=="IsolatedPlaintext"};
    internal static SMTPService Service(Cor23HSmtpServer server,string mode,Logs? logs=null,bool trustRoot=true)
    {
        var settings=Settings(server,mode);return new(Options.Create(settings),Options.Create(new EmailTemplateSettings()),logs??new Logs(),new(settings,"Testing"),server.Clients(trustRoot));
    }
    internal static void SecureTranscript(Cor23HSmtpServer server,bool submitted)
    {
        Assert.NotEmpty(server.Sessions);
        foreach(var session in server.Sessions)
        {
            Assert.All(session.Commands.Where(c=>c.Verb is "AUTH" or "MAIL" or "RCPT" or "DATA"),c=>Assert.True(c.Encrypted));
            if(submitted){Assert.True(session.Accepted);Assert.Contains(session.Commands,c=>c.Verb=="AUTH");Assert.Contains(session.Commands,c=>c.Verb=="DATA");}
            else Assert.False(session.Accepted);
        }
    }
    [Theory]
    [InlineData("RequiredStartTls")] [InlineData("ImplicitTls")]
    public async Task Required_TLS_with_valid_fixture_chain_and_expected_host_precedes_AUTH_and_DATA(string mode)
    {
        await using var server=new Cor23HSmtpServer(mode);var logs=new Logs();var smtp=Service(server,mode,logs);
        Assert.Equal(DeliverySendState.Accepted,(await smtp.SendDurable(Guid.NewGuid(),new("verify","email","recipient@example.test","Verify","proof-sentinel"),TestContext.Current.CancellationToken)).State);
        SecureTranscript(server,true);Assert.Contains("proof-sentinel",Assert.Single(server.Sessions).Message);Assert.Empty(logs.Messages);
    }
    [Theory]
    [InlineData("RequiredStartTls","untrusted")] [InlineData("ImplicitTls","untrusted")]
    [InlineData("RequiredStartTls","expired")] [InlineData("ImplicitTls","expired")]
    [InlineData("RequiredStartTls","wrong-host")] [InlineData("ImplicitTls","wrong-host")]
    public async Task Certificate_chain_expiry_and_hostname_failures_stop_before_credentials_or_message(string mode,string fault)
    {
        await using var server=new Cor23HSmtpServer(mode,fault);var logs=new Logs();var smtp=Service(server,mode,logs,trustRoot:fault!="untrusted");
        Assert.Equal(DeliverySendState.NotSubmitted,(await smtp.SendDurable(Guid.NewGuid(),new("verify","email","recipient@example.test","Verify","proof-sentinel"),TestContext.Current.CancellationToken)).State);
        SecureTranscript(server,false);Assert.All(server.Sessions,s=>Assert.DoesNotContain(s.Commands,c=>c.Verb is "AUTH" or "MAIL" or "DATA"));
        AssertSanitized(logs);
    }
    [Theory]
    [InlineData("missing-starttls")] [InlineData("reject-starttls")] [InlineData("plaintext-after-upgrade")]
    public async Task Missing_refused_or_fake_STARTTLS_never_downgrades_to_plaintext_AUTH_or_DATA(string fault)
    {
        await using var server=new Cor23HSmtpServer("RequiredStartTls",fault);var logs=new Logs();
        Assert.False(await Service(server,"RequiredStartTls",logs).Send("recipient@example.test","Verify","proof-sentinel"));
        SecureTranscript(server,false);Assert.All(server.Sessions,s=>Assert.DoesNotContain(s.Commands,c=>c.Verb is "AUTH" or "MAIL" or "DATA"));AssertSanitized(logs);
    }
    [Theory]
    [InlineData("RequiredStartTls")] [InlineData("ImplicitTls")]
    public async Task Required_TLS_modes_reject_a_plaintext_relay_despite_advertised_AUTH(string mode)
    {
        await using var server=new Cor23HSmtpServer("IsolatedPlaintext");
        Assert.Equal(DeliverySendState.NotSubmitted,(await Service(server,mode).SendDurable(Guid.NewGuid(),new("verify","email","recipient@example.test","Verify","proof-sentinel"),TestContext.Current.CancellationToken)).State);
        SecureTranscript(server,false);Assert.All(server.Sessions,s=>Assert.DoesNotContain(s.Commands,c=>c.Verb is "AUTH" or "MAIL" or "DATA"));
    }
    [Theory]
    [InlineData("RequiredStartTls")] [InlineData("ImplicitTls")]
    public async Task Authentication_rejection_is_encrypted_and_sanitized_and_never_submits_DATA(string mode)
    {
        await using var server=new Cor23HSmtpServer(mode,"reject-auth");var logs=new Logs();
        Assert.False(await Service(server,mode,logs).Send("recipient@example.test","Verify","proof-sentinel"));
        SecureTranscript(server,false);Assert.All(server.Sessions,s=> {Assert.Contains(s.Commands,c=>c.Verb=="AUTH"&&c.Encrypted);Assert.DoesNotContain(s.Commands,c=>c.Verb=="DATA");});AssertSanitized(logs);
    }
    [Theory]
    [InlineData("RequiredStartTls")] [InlineData("ImplicitTls")]
    public async Task Every_public_security_mail_method_and_durable_kind_uses_the_same_required_TLS_boundary(string mode)
    {
        await using var server=new Cor23HSmtpServer(mode);var smtp=Service(server,mode);
        var calls=new List<Func<Task<bool?>>>{()=>smtp.VerificationLetter("recipient@example.test","Verify","proof-sentinel"),()=>smtp.ResendVerifyLetter("recipient@example.test","Verify","proof-sentinel"),()=>smtp.EmailChangeVerifyLetter("recipient@example.test","Verify","proof-sentinel"),()=>smtp.DeleteAccountTwoStepLetter("recipient@example.test","Verify","proof-sentinel","code-sentinel"),()=>smtp.AccountUnlockLetter("recipient@example.test","Verify","proof-sentinel"),()=>smtp.TwoFactorSetupLetter("recipient@example.test","Verify","proof-sentinel"),()=>smtp.TwoFactorKeyOutboundLetter("recipient@example.test","Verify","proof-sentinel"),()=>smtp.TwoFactorDeleteLetter("recipient@example.test","Verify","proof-sentinel"),()=>smtp.PasswordResetCodeLetter("recipient@example.test","Verify","proof-sentinel","later","masked"),()=>smtp.Send("recipient@example.test","Verify","proof-sentinel")};
        foreach(string kind in new[]{"verify-start","verify","email","delete","unlock","activation-code","factor","reset"})
            calls.Add(async()=>(await smtp.SendDurable(Guid.NewGuid(),new(kind,"email","recipient@example.test","Verify","proof-sentinel","code-sentinel","masked"),TestContext.Current.CancellationToken)).State==DeliverySendState.Accepted);
        foreach(var call in calls)Assert.True(await call());Assert.Equal(18,server.Sessions.Count);SecureTranscript(server,true);
    }
    [Fact]
    public async Task Explicit_Testing_loopback_plaintext_relay_is_usable_without_enabling_a_deployable_exception()
    {
        await using var server=new Cor23HSmtpServer("IsolatedPlaintext");
        Assert.True(await Service(server,"IsolatedPlaintext").Send("recipient@example.test","Verify","proof-sentinel"));
        var session=Assert.Single(server.Sessions);Assert.True(session.Accepted);Assert.Contains(session.Commands,c=>c.Verb=="AUTH"&&!c.Encrypted);Assert.Contains(session.Commands,c=>c.Verb=="DATA"&&!c.Encrypted);
    }
    [Theory]
    [InlineData("RequiredStartTls")] [InlineData("ImplicitTls")]
    public async Task TLS_downgrade_below_the_supported_floor_never_authenticates_or_submits(string mode)
    {
#pragma warning disable SYSLIB0039
        await using var server=new Cor23HSmtpServer(mode,protocols:SslProtocols.Tls11);
#pragma warning restore SYSLIB0039
        Assert.Equal(DeliverySendState.NotSubmitted,(await Service(server,mode).SendDurable(Guid.NewGuid(),new("verify","email","recipient@example.test","Verify","proof-sentinel"),TestContext.Current.CancellationToken)).State);
        SecureTranscript(server,false);Assert.All(server.Sessions,s=>Assert.DoesNotContain(s.Commands,c=>c.Verb is "AUTH" or "DATA"));
    }
    [Fact]
    public async Task Mutable_options_cannot_switch_a_constructed_service_into_plaintext()
    {
        await using var server=new Cor23HSmtpServer("RequiredStartTls");var settings=Settings(server,"RequiredStartTls");
        var smtp=new SMTPService(Options.Create(settings),Options.Create(new EmailTemplateSettings()),new Logs(),new(settings,"Testing"),server.Clients());
        settings.TransportMode=SmtpTransportMode.IsolatedPlaintext;settings.AllowIsolatedPlaintext=true;settings.SMTPPassword="changed";
        Assert.True(await smtp.Send("recipient@example.test","Verify","proof-sentinel"));SecureTranscript(server,true);
    }
    private static void AssertSanitized(Logs logs)
    {
        Assert.NotEmpty(logs.Messages);string text=string.Join('\n',logs.Messages);
        foreach(string secret in new[]{"fixture-user-secret","fixture-password-secret","proof-sentinel","secret-provider-detail","recipient@example.test"})Assert.DoesNotContain(secret,text);
    }
}
