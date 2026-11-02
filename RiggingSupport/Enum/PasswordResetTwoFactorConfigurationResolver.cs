namespace treehammock.RiggingSupport.Enum;

public static class PasswordResetTwoFactorConfigurationResolver
{
    public static List<TwoFactorAuthConfiguration> AvailableFromMethods(
        IEnumerable<TwoFactorAuthMethod>? methods,
        PasswordResetBootstrapProof bootstrapProof)
    {
        if (methods is null)
        {
            return [];
        }

        HashSet<TwoFactorAuthMethod> uniqueMethods = methods
            .Where(method => method is not TwoFactorAuthMethod.NONE)
            .ToHashSet();

        ApplyBootstrapExclusions(uniqueMethods, bootstrapProof);

        return TwoFactorAuthConfigurationResolver.AvailableFromMethods(uniqueMethods);
    }

    public static List<TwoFactorAuthConfiguration> AvailableFromAccountSnapshot(
        bool emailVerified,
        bool smsVerified,
        bool authenticatorVerified,
        PasswordResetBootstrapProof bootstrapProof)
    {
        var methods = new List<TwoFactorAuthMethod>(capacity: 3);

        if (smsVerified)
        {
            methods.Add(TwoFactorAuthMethod.SMS_KEY);
        }

        if (emailVerified)
        {
            methods.Add(TwoFactorAuthMethod.EMAIL);
        }

        if (authenticatorVerified)
        {
            methods.Add(TwoFactorAuthMethod.AUTHENTICATOR_APP);
        }

        return AvailableFromMethods(methods, bootstrapProof);
    }

    private static void ApplyBootstrapExclusions(
        HashSet<TwoFactorAuthMethod> methods,
        PasswordResetBootstrapProof bootstrapProof)
    {
        switch (bootstrapProof)
        {
            case PasswordResetBootstrapProof.EmailResetToken:
                methods.Remove(TwoFactorAuthMethod.EMAIL);
                break;
            case PasswordResetBootstrapProof.SmsResetToken:
                methods.Remove(TwoFactorAuthMethod.SMS_KEY);
                break;
            case PasswordResetBootstrapProof.None:
            case PasswordResetBootstrapProof.AdminIssuedToken:
            default:
                break;
        }
    }
}
