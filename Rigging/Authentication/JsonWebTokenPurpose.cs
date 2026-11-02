namespace treehammock.Rigging.Authorization;

public static class JsonWebTokenPurpose
{
    public const string ClaimType = Treehammock.SessionValidation.Core.TreehammockTokenPurpose.ClaimType;
    public const string WebKeyClaimType = Treehammock.SessionValidation.Core.TreehammockTokenPurpose.WebKeyClaimType;
    public const string Active = Treehammock.SessionValidation.Core.TreehammockTokenPurpose.Active;
    public const string PreAuthTwoFactor = Treehammock.SessionValidation.Core.TreehammockTokenPurpose.PreAuthTwoFactor;
}
