using System.ComponentModel.DataAnnotations;

namespace treehammock.Rigging.Config;

internal static class ConfigurationValidation
{
    public static bool TryValidate<TOptions>(TOptions options, out string message)
        where TOptions : class
    {
        var validationResults = new List<ValidationResult>();
        bool valid = Validator.TryValidateObject(
            options,
            new ValidationContext(options),
            validationResults,
            validateAllProperties: true);

        if (!valid)
        {
            message = string.Join("; ", validationResults.Select(result => result.ErrorMessage));
            return false;
        }

        message = options switch
        {
            DatabaseSettings db when db.minimumPoolSize > db.maximumPoolSize => "Database minimum pool size cannot exceed maximum pool size.",
            DatabaseSettings db when !string.Equals(db.profile, "Local", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(db.profile, "Production", StringComparison.OrdinalIgnoreCase) => "Database profile must be Local or Production.",
            JWTSettings jwt when !HasPositiveDuration(jwt.RefreshTokenAliveDays, jwt.RefreshTokenAliveHours, jwt.RefreshTokenAliveMinutes) =>
                "JWTSettings cache refresh-token lifetime must be greater than zero.",
            JWTSettings jwt when !HasPositiveDuration(jwt.RefreshTokenAliveDays_2FA, jwt.RefreshTokenAliveHours_2FA, jwt.RefreshTokenAliveMinutes_2FA) =>
                "JWTSettings 2FA pre-auth token lifetime must be greater than zero.",
            JWTSettings jwt when !HasPositiveDuration(jwt.RefreshTokenAliveDays_DB, jwt.RefreshTokenAliveHours_DB, jwt.RefreshTokenAliveMinutes_DB) =>
                "JWTSettings database refresh-token lifetime must be greater than zero.",
            JWTSettings jwt when !HasPositiveDuration(jwt.RefreshTokenAliveDays_Short, jwt.RefreshTokenAliveHours_Short, jwt.RefreshTokenAliveMinutes_Short) =>
                "JWTSettings short refresh-token lifetime must be greater than zero.",
            JWTSettings jwt when jwt.MinimumRefreshIntervalSeconds > jwt.RefreshTokenAliveDays_Short * 86400L + jwt.RefreshTokenAliveHours_Short * 3600L + jwt.RefreshTokenAliveMinutes_Short * 60L =>
                "JWTSettings minimum refresh interval must not exceed the access lifetime.",
            RegistrationSettings registration when registration.MinUsernameLength > registration.MaxUsernameLength =>
                "RegistrationSettings MinUsernameLength cannot exceed MaxUsernameLength.",
            RegistrationSettings registration when registration.MinPasswordLength > registration.MaxPasswordLength =>
                "RegistrationSettings MinPasswordLength cannot exceed MaxPasswordLength.",
            SidewalkSettings sidewalk => ValidateSidewalkSettings(sidewalk),
            _ => string.Empty
        };

        return string.IsNullOrEmpty(message);
    }

    private static string ValidateSidewalkSettings(SidewalkSettings sidewalk)
    {
        if (!sidewalk.SmsEnabled)
        {
            return string.Empty;
        }

        IReadOnlyList<string> providers = SmsProviderNames.NormalizeConfiguredProviders(sidewalk);
        if (providers.Count == 0)
        {
            return "SidewalkSettings SMS delivery requires at least one configured SMS provider name.";
        }

        string? unsupportedProvider = providers.FirstOrDefault(provider => !SmsProviderNames.IsSupported(provider));
        if (unsupportedProvider is not null)
        {
            return "SidewalkSettings:SmsProviderPrimary/SidewalkSettings:SmsProviderSecondary contains an unsupported provider. Supported providers are aws-sns and twilio.";
        }

        if (providers.Count != providers.Distinct(StringComparer.OrdinalIgnoreCase).Count())
        {
            return "SidewalkSettings SMS provider chain cannot contain duplicate providers after alias normalization.";
        }

        if (!sidewalk.AwsSnsEnabled && !sidewalk.TwilioEnabled)
        {
            return "SidewalkSettings SMS delivery requires at least one enabled SMS provider feature flag.";
        }

        string? disabledConfiguredProvider = providers.FirstOrDefault(provider => !SmsProviderNames.IsEnabled(sidewalk, provider));
        if (disabledConfiguredProvider is not null)
        {
            return "SidewalkSettings:SmsProviderPrimary/SidewalkSettings:SmsProviderSecondary selects a disabled provider feature flag.";
        }

        if (!providers.Any(provider => SmsProviderNames.IsEnabled(sidewalk, provider)))
        {
            return "SidewalkSettings SMS delivery requires at least one configured provider with an enabled feature flag.";
        }

        return string.Empty;
    }

    private static bool HasPositiveDuration(int days, int hours, int minutes)
    {
        return days > 0 || hours > 0 || minutes > 0;
    }
}
