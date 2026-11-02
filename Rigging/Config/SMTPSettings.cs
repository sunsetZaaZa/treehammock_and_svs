using System.ComponentModel.DataAnnotations;
using System.Net;

namespace treehammock.Rigging.Config;

public enum SmtpTransportMode { RequiredStartTls, ImplicitTls, IsolatedPlaintext }

public class SMTPSettings : IValidatableObject
{
    public SmtpTransportMode TransportMode { get; set; } = SmtpTransportMode.RequiredStartTls;
    public bool AllowIsolatedPlaintext { get; set; }
    [Required]
    public string SMTPQualifiedDomain { get; set; } = string.Empty;

    [Range(1, 65535)]
    public int SMTPPort { get; set; }

    [Required]
    public string SMTPUsername { get; set; } = string.Empty;

    [Required]
    public string SMTPPassword { get; set; } = string.Empty;

    [Required]
    [EmailAddress]
    public string NoReplyEmailAddress { get; set; } = string.Empty;

    public IEnumerable<ValidationResult> Validate(ValidationContext context)
    {
        if (!Enum.IsDefined(TransportMode))
            yield return new("SMTPSettings TransportMode is unsupported.", [nameof(TransportMode)]);
        if (string.IsNullOrWhiteSpace(SMTPQualifiedDomain) || SMTPQualifiedDomain.Any(char.IsWhiteSpace) ||
            SMTPQualifiedDomain.Any(char.IsControl) || Uri.CheckHostName(SMTPQualifiedDomain) == UriHostNameType.Unknown)
            yield return new("SMTPSettings SMTPQualifiedDomain must be a hostname or IP address, without a URL or port.", [nameof(SMTPQualifiedDomain)]);
        if (TransportMode == SmtpTransportMode.IsolatedPlaintext)
        {
            if (!AllowIsolatedPlaintext || !IPAddress.TryParse(SMTPQualifiedDomain, out var address) || !IPAddress.IsLoopback(address))
                yield return new("SMTPSettings plaintext requires explicit permission and a literal loopback address.", [nameof(AllowIsolatedPlaintext), nameof(SMTPQualifiedDomain)]);
        }
        else if (AllowIsolatedPlaintext)
            yield return new("SMTPSettings AllowIsolatedPlaintext conflicts with the selected secure transport.", [nameof(AllowIsolatedPlaintext)]);
        if ((TransportMode == SmtpTransportMode.RequiredStartTls && SMTPPort == 465) ||
            (TransportMode == SmtpTransportMode.ImplicitTls && SMTPPort == 587))
            yield return new("SMTPSettings transport conflicts with the conventional submission port.", [nameof(TransportMode), nameof(SMTPPort)]);
    }
}
