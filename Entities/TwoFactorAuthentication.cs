using System.Diagnostics.CodeAnalysis;

using NodaTime;

using treehammock.RiggingSupport.Enum;

namespace treehammock.Entities;

//When setting up a two factor auth with a phoneNumber that does not match the phoneNumber of the phone
//setting up the 2FA. An email is sent to the user asking to verify the process before anymore steps of the 2FA
//setup are made avialble to the user.
public class TwoFactorAuthentication
{
    [SetsRequiredMembers]
    public TwoFactorAuthentication(short index, Guid accountId, string token, string? authId, Instant createdOn, Period lifespan, Instant? expiration,
                                    TwoFactorAuthMethod method, bool verified, short priority, Country country, string? emailAddress, string? phoneNumber, string? phoneCountryCode,
                                    bool required, byte[]? totpSecretCiphertext = null, byte[]? totpSecretNonce = null, byte[]? totpSecretTag = null, int totpSecretVersion = 1, long? totpLastUsedStep = null, short totpProviderType = 1, string? totpProviderEnrollmentId = null, string? totpProviderAccountBindingHash = null)
    {
        (this.index, this.accountId, this.token, this.authId, this.createdOn, this.lifespan, this.expiration, this.method, this.verified, this.priority, this.country, 
            this.emailAddress, this.phoneNumber, this.phoneCountryCode, this.required, this.totpSecretCiphertext, this.totpSecretNonce, this.totpSecretTag, this.totpSecretVersion, this.totpLastUsedStep, this.totpProviderType, this.totpProviderEnrollmentId, this.totpProviderAccountBindingHash) = 
        (index, accountId, token, authId, createdOn, lifespan, expiration, method, verified, priority, country, emailAddress, phoneNumber, phoneCountryCode, required, totpSecretCiphertext, totpSecretNonce, totpSecretTag, totpSecretVersion, totpLastUsedStep, totpProviderType, totpProviderEnrollmentId, totpProviderAccountBindingHash);
    }

    public required short index { get; set; }
    public required Guid accountId { get; set; }
    public required string? authId { get; set; }
    public required string? token { get; set; }
    public required Instant createdOn { get; set;}
    public required Period? lifespan { get; set; }
    public required Instant? expiration { get; set; }
    public required TwoFactorAuthMethod method { get; set; }
    public required bool verified { get; set; }
    public required short priority { get; set; }
    public Country? country { get; set; }
    public string? emailAddress { get; set; }
    public string? phoneNumber { get; set; }
    public string? phoneCountryCode { get; set; }
    public required bool required { get; set; }
    public byte[]? totpSecretCiphertext { get; set; }
    public byte[]? totpSecretNonce { get; set; }
    public byte[]? totpSecretTag { get; set; }
    public int totpSecretVersion { get; set; } = 1;
    public long? totpLastUsedStep { get; set; }
    public short totpProviderType { get; set; } = 1;
    public string? totpProviderEnrollmentId { get; set; }
    public string? totpProviderAccountBindingHash { get; set; }
}
