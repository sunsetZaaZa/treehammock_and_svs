using System.ComponentModel.DataAnnotations;

namespace treehammock.Rigging.Config;

public class SidewalkSettings
{
    public string? ElasticSearch { get; set; }

    public bool SmsEnabled { get; set; }

    public bool AwsSnsEnabled { get; set; }

    public bool TwilioEnabled { get; set; }

    public string? SmsProviderPrimary { get; set; } = "aws";

    public string? SmsProviderSecondary { get; set; } = "twilio";

    public string? TwilioAccountSid { get; set; }

    public string? TwilioAuthToken { get; set; }

    public string? TwilioFromPhoneNumber { get; set; }

    [Required]
    public string PaymentProcessorPrimary { get; set; } = string.Empty;

    public string? PaymentProcessorSecondary { get; set; }

    [Range(0, short.MaxValue)]
    public short? SMSHardStop { get; set; }
}
