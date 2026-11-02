namespace treehammock.Rigging.Security;

public static class AccountSecurityStampGuard
{
    public static Guid Require(Guid? accountSecurityStamp, string parameterName = "accountSecurityStamp")
    {
        if (accountSecurityStamp is null || accountSecurityStamp == Guid.Empty)
        {
            throw new ArgumentException("An account security stamp is required and must be loaded from the account row.", parameterName);
        }

        return accountSecurityStamp.Value;
    }
}
