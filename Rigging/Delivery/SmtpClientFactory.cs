using System.Security.Authentication;
using MailKit.Net.Smtp;

namespace treehammock.Rigging.Delivery;

// Per-send client ownership; the test seam supplies a real client with isolated fixture CA trust.
public interface ISmtpClientFactory { SmtpClient Create(); }
public sealed class SmtpClientFactory : ISmtpClientFactory
{
    public SmtpClient Create() => new()
    {
        Timeout = 20000,
        SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
        CheckCertificateRevocation = true
        // Leave ServerCertificateValidationCallback unset: normal chain/time/hostname validation.
    };
}
