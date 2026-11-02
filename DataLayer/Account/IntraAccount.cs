using treehammock.DataLayer.Cache;
using treehammock.Rigging.Security;
using treehammock.RiggingSupport.Enum;
using NodaTime;
using System.Diagnostics.CodeAnalysis;

namespace treehammock.DataLayer.Account;

public class IntraAccount
{
    [SetsRequiredMembers]
    public IntraAccount(Guid accountId, byte[] hashedPassword, string webKey, VerificationStatus verifyStatus, byte[] saltOne, byte[] siv, byte[] nonce, Instant? unlockWhen,
                            byte[]? refreshToken, short refreshes, short limit, Period? lifespan, short loginFailures, string? twoFactorAccessToken, short authenticatorAppUsage, short smsKeyUsage, short smsUsage,
                            bool hasTwoFactorAuth, Country country, Instant? cutOff, AccountLockDown? lockedDown, FeatureSet features, string? activeAccessTokenHash = null, Guid? accountSecurityStamp = null)
    {
        (this.accountId, this.hashedPassword, this.webKey, this.verifyStatus, this.saltOne, this.siv, this.nonce, this.unlockWhen, this.refreshToken, this.refreshes, this.limit, 
            this.lifespan, this.loginFailures ,this.twoFactorAccessToken, this.authenticatorAppUsage, this.smsKeyUsage, this.smsUsage, this.hasTwoFactorAuth, this.country, this.cutOff, this.lockedDown, this.features, this.twoFactorAuthMethod, this.activeAccessTokenHash, this.accountSecurityStamp) =
        (accountId, hashedPassword, webKey, verifyStatus, saltOne, siv, nonce, unlockWhen ,refreshToken, refreshes, limit, lifespan, loginFailures, twoFactorAccessToken,
            authenticatorAppUsage, smsKeyUsage, smsUsage, hasTwoFactorAuth, country, cutOff, lockedDown, features, TwoFactorAuthMethod.NONE, activeAccessTokenHash, AccountSecurityStampGuard.Require(accountSecurityStamp));
    }


    [SetsRequiredMembers]
    public IntraAccount(Guid accountId, byte[] hashedPassword, string webKey, byte[]? refreshToken, short refreshes, short limit, Instant createdOn,
                            Period? lifespan, byte[] saltOne, byte[] siv, byte[] nonce, Instant? unlockWhen, short loginFailures, VerificationStatus verifyStatus,
                            FeatureSet features, string? twoFactorAccessToken, TwoFactorAuthMethod twoFactorAuthMethod, short twoAuthUsage, Instant? cutOff = null, string? activeAccessTokenHash = null, Guid? accountSecurityStamp = null)
    {
        bool usesTwoFactor = twoFactorAuthMethod != TwoFactorAuthMethod.NONE;

        (this.accountId, this.hashedPassword, this.webKey, this.verifyStatus, this.saltOne, this.siv, this.nonce, this.unlockWhen, this.refreshToken, this.refreshes, this.limit,
            this.lifespan, this.loginFailures, this.twoFactorAccessToken, this.authenticatorAppUsage, this.smsKeyUsage, this.smsUsage, this.hasTwoFactorAuth, this.country, this.cutOff, this.lockedDown, this.features, this.twoFactorAuthMethod, this.activeAccessTokenHash, this.accountSecurityStamp) =
        (accountId, hashedPassword, webKey, verifyStatus, saltOne, siv, nonce, unlockWhen, refreshToken, refreshes, limit, lifespan, loginFailures, twoFactorAccessToken,
            twoAuthUsage, twoAuthUsage, twoAuthUsage, usesTwoFactor, Country.NONE, cutOff, null, features, twoFactorAuthMethod, activeAccessTokenHash, AccountSecurityStampGuard.Require(accountSecurityStamp));
    }

    public required Guid accountId { get; set; }
    public required byte[] hashedPassword { get; set; }
    public required string webKey { get; set; }
    public required VerificationStatus verifyStatus { get; set; }
    public required byte[] saltOne { get; set; }
    public required byte[] siv { get; set; }
    public required byte[] nonce { get; set; }
    public Instant? unlockWhen { get; set; }
    public byte[]? refreshToken { get; set; }
    public required short refreshes { get; set; }
    public required short limit { get; set; }
    public required Period? lifespan { get; set; } // Length of time the refreshToken is valid for - NULL is indefinite
    public required short loginFailures { get; set; }
    public Guid loginAttemptVersion { get; set; }
    public string? twoFactorAccessToken { get; set; }
    public required short authenticatorAppUsage { get; set; }
    public required short smsKeyUsage { get; set; }
    public required short smsUsage { get; set; }
    public bool hasTwoFactorAuth { get; set; }
    public required TwoFactorAuthMethod twoFactorAuthMethod { get; set; }
    public required Country country { get; set; }
    public required Instant? cutOff { get; set; }
    public required AccountLockDown? lockedDown { get; set; }
    public treehammock.DataLayer.Entitlements.EntitlementProjection? entitlements { get; set; }
    public required FeatureSet features { get; set; }
    public string? activeAccessTokenHash { get; set; }
    public required Guid accountSecurityStamp { get; set; }
}
