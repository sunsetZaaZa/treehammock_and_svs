namespace treehammock.RiggingSupport.Enum;

public enum TwoFactorAuthConfiguration
{
    NONE = 0,
    SMS = 1,
    EMAIL = 2,
    AUTHENTICATOR_APP = 3,
    SMS_AND_AUTHENTICATOR_APP = 4,
    EMAIL_AND_AUTHENTICATOR_APP = 5,
    CUSTOM = 6
}

public static class TwoFactorAuthConfigurationResolver
{
    public static TwoFactorAuthConfiguration FromMethods(IEnumerable<TwoFactorAuthMethod>? methods)
    {
        if (methods is null)
        {
            return TwoFactorAuthConfiguration.NONE;
        }

        HashSet<TwoFactorAuthMethod> uniqueMethods = methods
            .Where(method => method is not TwoFactorAuthMethod.NONE)
            .ToHashSet();

        bool hasEmail = uniqueMethods.Contains(TwoFactorAuthMethod.EMAIL);
        bool hasSms = uniqueMethods.Contains(TwoFactorAuthMethod.SMS_KEY);
        bool hasAuthenticatorApp = uniqueMethods.Contains(TwoFactorAuthMethod.AUTHENTICATOR_APP);

        return (hasEmail, hasSms, hasAuthenticatorApp) switch
        {
            (false, false, false) => TwoFactorAuthConfiguration.NONE,
            (false, true, false) => TwoFactorAuthConfiguration.SMS,
            (true, false, false) => TwoFactorAuthConfiguration.EMAIL,
            (false, false, true) => TwoFactorAuthConfiguration.AUTHENTICATOR_APP,
            (false, true, true) => TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP,
            (true, false, true) => TwoFactorAuthConfiguration.EMAIL_AND_AUTHENTICATOR_APP,
            _ => TwoFactorAuthConfiguration.CUSTOM
        };
    }

    public static List<TwoFactorAuthConfiguration> AvailableFromMethods(IEnumerable<TwoFactorAuthMethod>? methods)
    {
        if (methods is null)
        {
            return [];
        }

        HashSet<TwoFactorAuthMethod> uniqueMethods = methods
            .Where(method => method is not TwoFactorAuthMethod.NONE)
            .ToHashSet();

        bool hasSms = uniqueMethods.Contains(TwoFactorAuthMethod.SMS_KEY);
        bool hasEmail = uniqueMethods.Contains(TwoFactorAuthMethod.EMAIL);
        bool hasAuthenticatorApp = uniqueMethods.Contains(TwoFactorAuthMethod.AUTHENTICATOR_APP);

        var available = new List<TwoFactorAuthConfiguration>();

        if (hasSms)
        {
            available.Add(TwoFactorAuthConfiguration.SMS);
        }

        if (hasEmail)
        {
            available.Add(TwoFactorAuthConfiguration.EMAIL);
        }

        if (hasAuthenticatorApp)
        {
            available.Add(TwoFactorAuthConfiguration.AUTHENTICATOR_APP);
        }

        if (hasSms && hasAuthenticatorApp)
        {
            available.Add(TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP);
        }

        if (hasEmail && hasAuthenticatorApp)
        {
            available.Add(TwoFactorAuthConfiguration.EMAIL_AND_AUTHENTICATOR_APP);
        }

        return available;
    }
}
