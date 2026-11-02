using Microsoft.Extensions.Options;
using treehammock.Rigging.Hosting;

namespace treehammock.Rigging.Config;

// Local shape/prerequisite checks only; no secret value is returned and no network I/O occurs.
public static class TwilioTransportConfiguration
{
    public static IReadOnlyList<string> InvalidSettings(SidewalkSettings settings)
    {
        var invalid=new List<string>();
        string? sid=settings.TwilioAccountSid;
        if(sid is null || sid.Length!=34 || !sid.StartsWith("AC",StringComparison.Ordinal) || !sid.AsSpan(2).ToArray().All(char.IsAsciiHexDigit))
            invalid.Add(nameof(SidewalkSettings.TwilioAccountSid));
        string? token=settings.TwilioAuthToken;
        if(string.IsNullOrEmpty(token) || token.Length>512 || token.Any(c=>c<'!' || c>'~'))
            invalid.Add(nameof(SidewalkSettings.TwilioAuthToken));
        if(!IsSupportedSender(settings.TwilioFromPhoneNumber))
            invalid.Add(nameof(SidewalkSettings.TwilioFromPhoneNumber));
        return invalid;
    }
    // This phone-number setting supports E.164 SMS senders, not short codes or other channel addresses.
    public static bool IsSupportedSender(string? sender)
        => sender is not null && sender.Length is >=3 and <=16 && sender[0]=='+' && sender[1] is >= '1' and <= '9' && sender.AsSpan(2).ToArray().All(c=>c is >= '0' and <= '9');
}

public sealed class SelectedSmsTransportValidator(SystemTestCapability capability) : IValidateOptions<SidewalkSettings>
{
    public ValidateOptionsResult Validate(string? name,SidewalkSettings settings)
    {
        // Only the validated, immutable COR23D capture composition replaces all physical SMS adapters.
        if(capability.CaptureEnabled || !settings.SmsEnabled || !settings.TwilioEnabled ||
            !SmsProviderNames.NormalizeConfiguredProviders(settings).Contains(SmsProviderNames.Twilio,StringComparer.Ordinal))
            return ValidateOptionsResult.Success;
        var invalid=TwilioTransportConfiguration.InvalidSettings(settings);
        return invalid.Count==0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(
            invalid.Select(setting=>"SidewalkSettings:"+setting+" is missing or invalid."));
    }
}
