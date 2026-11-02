using MailKit.Security;
using Microsoft.Extensions.Options;
using treehammock.Rigging.Config;

namespace treehammock.Rigging.Delivery;

// Snapshot once per host. Reloads cannot enable plaintext or replace credentials mid-attempt.
public sealed class SmtpTransportPolicy
{
    public string Host { get; }
    public int Port { get; }
    public string Username { get; }
    public string Password { get; }
    public string Sender { get; }
    public SecureSocketOptions SocketOptions { get; }
    public bool RequireEncryption { get; }
    public static bool AllowedForEnvironment(SMTPSettings settings, string? environment)
        => ConfigurationValidation.TryValidate(settings, out _) &&
           (settings.TransportMode != SmtpTransportMode.IsolatedPlaintext || environment == "Testing");
    public SmtpTransportPolicy(SMTPSettings settings, string? environment)
    {
        if (!AllowedForEnvironment(settings, environment))
            throw new OptionsValidationException("SMTPSettings", typeof(SMTPSettings),
                ["SMTPSettings requires supported authenticated TLS; explicit loopback plaintext is restricted to Testing."]);
        Host = settings.SMTPQualifiedDomain; Port = settings.SMTPPort;
        Username = settings.SMTPUsername; Password = settings.SMTPPassword; Sender = settings.NoReplyEmailAddress;
        SocketOptions = settings.TransportMode switch
        {
            SmtpTransportMode.RequiredStartTls => SecureSocketOptions.StartTls,
            SmtpTransportMode.ImplicitTls => SecureSocketOptions.SslOnConnect,
            SmtpTransportMode.IsolatedPlaintext => SecureSocketOptions.None,
            _ => throw new InvalidOperationException("Unsupported SMTP transport.")
        };
        RequireEncryption = settings.TransportMode != SmtpTransportMode.IsolatedPlaintext;
    }
}
