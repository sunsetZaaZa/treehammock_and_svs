using NodaTime;
using Shouldly;

using treehammock.Repos;
using treehammock.Rigging.Security;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;

namespace treehammock.Tests.Unit;

public class AccountRepoMappingTests
{
    [Fact]
    public void MapCredentialColumns_preserves_column_values_in_IntraAccount_fields()
    {
        var accountId = Guid.NewGuid();
        const int refreshTokenBytes = 64;
        var hashedPassword = Enumerable.Range(0, AccountCryptoSizes.PasswordHashBytes).Select(i => (byte)i).ToArray();
        var refreshToken = Enumerable.Range(64, refreshTokenBytes).Select(i => (byte)i).ToArray();
        var saltOne = Enumerable.Range(1, AccountCryptoSizes.SaltOneBytes).Select(i => (byte)i).ToArray();
        var siv = Enumerable.Range(2, AccountCryptoSizes.SivBytes).Select(i => (byte)i).ToArray();
        var nonce = Enumerable.Range(3, AccountCryptoSizes.NonceBytes).Select(i => (byte)i).ToArray();
        var createdOn = Instant.FromUtc(2026, 5, 14, 18, 0);
        var unlockWhen = Instant.FromUtc(2026, 5, 14, 19, 0);
        var lifespan = Period.FromHours(1);
        var cutOff = Instant.FromUtc(2026, 5, 14, 20, 0);
        var accountSecurityStamp = Guid.Parse("11111111-2222-3333-4444-555555555555");

        var account = AccountRepo.MapCredentialColumns(
            accountId: accountId,
            hashedPassword: hashedPassword,
            webKey: "web-key",
            refreshToken: refreshToken,
            refreshes: 2,
            limit: 5,
            createdOn: createdOn,
            lifespan: lifespan,
            saltOne: saltOne,
            siv: siv,
            nonce: nonce,
            unlockWhen: unlockWhen,
            loginFailures: 1,
            verifyStatus: VerificationStatus.SUCCESSFUL,
            features: FeatureSet.basic,
            twoFactorAccessToken: "pending-token",
            twoFactorAuthMethod: TwoFactorAuthMethod.AUTHENTICATOR_APP,
            twoAuthUsage: 3,
            cutOff: cutOff,
            activeAccessTokenHash: "stored-active-hash",
            accountSecurityStamp: accountSecurityStamp);

        account.accountId.ShouldBe(accountId);
        account.hashedPassword.ShouldBe(hashedPassword);
        account.webKey.ShouldBe("web-key");
        account.refreshToken.ShouldBe(refreshToken);
        account.refreshes.ShouldBe((short)2);
        account.limit.ShouldBe((short)5);
        account.lifespan.ShouldBe(lifespan);
        account.saltOne.ShouldBe(saltOne);
        account.siv.ShouldBe(siv);
        account.nonce.ShouldBe(nonce);
        account.unlockWhen.ShouldBe(unlockWhen);
        account.loginFailures.ShouldBe((short)1);
        account.verifyStatus.ShouldBe(VerificationStatus.SUCCESSFUL);
        account.features.ShouldBe(FeatureSet.basic);
        account.twoFactorAccessToken.ShouldBe("pending-token");
        account.twoFactorAuthMethod.ShouldBe(TwoFactorAuthMethod.AUTHENTICATOR_APP);
        account.authenticatorAppUsage.ShouldBe((short)3);
        account.smsKeyUsage.ShouldBe((short)3);
        account.smsUsage.ShouldBe((short)3);
        account.hasTwoFactorAuth.ShouldBeTrue();
        account.cutOff.ShouldBe(cutOff);
        account.activeAccessTokenHash.ShouldBe("stored-active-hash");
        account.accountSecurityStamp.ShouldBe(accountSecurityStamp);
    }

    [Fact]
    public void MapCredentialColumns_allows_null_refresh_token_for_not_logged_in_accounts()
    {
        var account = AccountRepo.MapCredentialColumns(
            accountId: Guid.NewGuid(),
            hashedPassword: new byte[AccountCryptoSizes.PasswordHashBytes],
            webKey: "web-key",
            refreshToken: null,
            refreshes: 0,
            limit: 5,
            createdOn: Instant.FromUtc(2026, 5, 14, 18, 0),
            lifespan: null,
            saltOne: new byte[AccountCryptoSizes.SaltOneBytes],
            siv: new byte[AccountCryptoSizes.SivBytes],
            nonce: new byte[AccountCryptoSizes.NonceBytes],
            unlockWhen: null,
            loginFailures: 0,
            verifyStatus: VerificationStatus.SUCCESSFUL,
            features: FeatureSet.basic,
            twoFactorAccessToken: null,
            twoFactorAuthMethod: TwoFactorAuthMethod.NONE,
            twoAuthUsage: 0,
            accountSecurityStamp: Guid.Parse("22222222-3333-4444-5555-666666666666"));

        account.refreshToken.ShouldBeNull();
        account.hasTwoFactorAuth.ShouldBeFalse();
        account.twoFactorAuthMethod.ShouldBe(TwoFactorAuthMethod.NONE);
        account.accountSecurityStamp.ShouldBe(Guid.Parse("22222222-3333-4444-5555-666666666666"));
    }

    [Fact]
    public void IntraAccount_auth_path_constructor_preserves_account_cutoff()
    {
        Instant cutOff = Instant.FromUtc(2026, 5, 16, 19, 30);

        var account = new treehammock.DataLayer.Account.IntraAccount(
            accountId: Guid.NewGuid(),
            hashedPassword: new byte[AccountCryptoSizes.PasswordHashBytes],
            webKey: "web-key",
            refreshToken: null,
            refreshes: 0,
            limit: 5,
            createdOn: Instant.FromUtc(2026, 5, 16, 18, 0),
            lifespan: null,
            saltOne: new byte[AccountCryptoSizes.SaltOneBytes],
            siv: new byte[AccountCryptoSizes.SivBytes],
            nonce: new byte[AccountCryptoSizes.NonceBytes],
            unlockWhen: null,
            loginFailures: 0,
            verifyStatus: VerificationStatus.SUCCESSFUL,
            features: FeatureSet.basic,
            twoFactorAccessToken: null,
            twoFactorAuthMethod: TwoFactorAuthMethod.NONE,
            twoAuthUsage: 0,
            cutOff: cutOff,
            accountSecurityStamp: Guid.Parse("33333333-4444-5555-6666-777777777777"));

        account.cutOff.ShouldBe(cutOff);
    }
    [Fact]
    public void MapCredentialColumns_allows_variable_length_password_hash_material()
    {
        byte[] variableLengthPasswordHash = Enumerable.Repeat((byte)1, AccountCryptoSizes.PasswordHashBytes - 1).ToArray();

        var account = AccountRepo.MapCredentialColumns(
            accountId: Guid.NewGuid(),
            hashedPassword: variableLengthPasswordHash,
            webKey: "web-key",
            refreshToken: null,
            refreshes: 0,
            limit: 5,
            createdOn: Instant.FromUtc(2026, 5, 14, 18, 0),
            lifespan: null,
            saltOne: new byte[AccountCryptoSizes.SaltOneBytes],
            siv: new byte[AccountCryptoSizes.SivBytes],
            nonce: new byte[AccountCryptoSizes.NonceBytes],
            unlockWhen: null,
            loginFailures: 0,
            verifyStatus: VerificationStatus.SUCCESSFUL,
            features: FeatureSet.basic,
            twoFactorAccessToken: null,
            twoFactorAuthMethod: TwoFactorAuthMethod.NONE,
            twoAuthUsage: 0,
            accountSecurityStamp: Guid.Parse("44444444-5555-6666-7777-888888888888"));

        account.hashedPassword.ShouldBe(variableLengthPasswordHash);
    }

    [Fact]
    public void MapCredentialColumns_rejects_empty_password_hash_material()
    {
        Should.Throw<System.Data.DataException>(() => AccountRepo.MapCredentialColumns(
            accountId: Guid.NewGuid(),
            hashedPassword: Array.Empty<byte>(),
            webKey: "web-key",
            refreshToken: null,
            refreshes: 0,
            limit: 5,
            createdOn: Instant.FromUtc(2026, 5, 14, 18, 0),
            lifespan: null,
            saltOne: new byte[AccountCryptoSizes.SaltOneBytes],
            siv: new byte[AccountCryptoSizes.SivBytes],
            nonce: new byte[AccountCryptoSizes.NonceBytes],
            unlockWhen: null,
            loginFailures: 0,
            verifyStatus: VerificationStatus.SUCCESSFUL,
            features: FeatureSet.basic,
            twoFactorAccessToken: null,
            twoFactorAuthMethod: TwoFactorAuthMethod.NONE,
            twoAuthUsage: 0,
            accountSecurityStamp: Guid.Parse("44444444-5555-6666-7777-888888888888")));
    }

    [Fact]
    public void MapCredentialColumns_rejects_wrong_salt_siv_or_nonce_length()
    {
        Should.Throw<System.Data.DataException>(() => AccountRepo.MapCredentialColumns(
            accountId: Guid.NewGuid(),
            hashedPassword: new byte[AccountCryptoSizes.PasswordHashBytes],
            webKey: "web-key",
            refreshToken: null,
            refreshes: 0,
            limit: 5,
            createdOn: Instant.FromUtc(2026, 5, 14, 18, 0),
            lifespan: null,
            saltOne: new byte[AccountCryptoSizes.SaltOneBytes - 1],
            siv: new byte[AccountCryptoSizes.SivBytes],
            nonce: new byte[AccountCryptoSizes.NonceBytes],
            unlockWhen: null,
            loginFailures: 0,
            verifyStatus: VerificationStatus.SUCCESSFUL,
            features: FeatureSet.basic,
            twoFactorAccessToken: null,
            twoFactorAuthMethod: TwoFactorAuthMethod.NONE,
            twoAuthUsage: 0,
            accountSecurityStamp: Guid.Parse("44444444-5555-6666-7777-888888888888")));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("00000000-0000-0000-0000-000000000000")]
    public void MapCredentialColumns_rejects_missing_or_empty_account_security_stamp(string? stampText)
    {
        Guid? stamp = stampText is null ? null : Guid.Parse(stampText);

        Should.Throw<ArgumentException>(() => AccountRepo.MapCredentialColumns(
            accountId: Guid.NewGuid(),
            hashedPassword: new byte[AccountCryptoSizes.PasswordHashBytes],
            webKey: "web-key",
            refreshToken: null,
            refreshes: 0,
            limit: 5,
            createdOn: Instant.FromUtc(2026, 5, 14, 18, 0),
            lifespan: null,
            saltOne: new byte[AccountCryptoSizes.SaltOneBytes],
            siv: new byte[AccountCryptoSizes.SivBytes],
            nonce: new byte[AccountCryptoSizes.NonceBytes],
            unlockWhen: null,
            loginFailures: 0,
            verifyStatus: VerificationStatus.SUCCESSFUL,
            features: FeatureSet.basic,
            twoFactorAccessToken: null,
            twoFactorAuthMethod: TwoFactorAuthMethod.NONE,
            twoAuthUsage: 0,
            accountSecurityStamp: stamp));
    }

}
