namespace treehammock.Rigging.Config;

public static class SmsProviderNames
{
    public const string AwsSns = "aws-sns";
    public const string Twilio = "twilio";

    public static string? Normalize(string? providerName)
    {
        if (string.IsNullOrWhiteSpace(providerName))
        {
            return null;
        }

        return providerName.Trim().ToLowerInvariant() switch
        {
            "aws" or "sns" or AwsSns => AwsSns,
            Twilio => Twilio,
            var unknown => unknown
        };
    }

    public static bool IsSupported(string? providerName)
    {
        string? normalized = Normalize(providerName);
        return normalized is AwsSns or Twilio;
    }

    public static bool IsEnabled(SidewalkSettings settings, string? providerName)
    {
        return Normalize(providerName) switch
        {
            AwsSns => settings.AwsSnsEnabled,
            Twilio => settings.TwilioEnabled,
            _ => false
        };
    }

    public static IReadOnlyList<string> NormalizeConfiguredProviders(SidewalkSettings settings)
    {
        var providers = new List<string>();

        AddIfPresent(settings.SmsProviderPrimary);
        AddIfPresent(settings.SmsProviderSecondary);

        return providers;

        void AddIfPresent(string? providerName)
        {
            string? normalized = Normalize(providerName);
            if (normalized is not null)
            {
                providers.Add(normalized);
            }
        }
    }
}
