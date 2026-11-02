using Microsoft.Extensions.Options;
using Shouldly;

using treehammock.Rigging.Config;
using treehammock.Rigging.Security;
using treehammock.Services;

namespace treehammock.Tests.Unit;

public class PasswordResetPasswordMaterialFactoryTests
{
    [Fact]
    public void CreatePasswordMaterial_returns_account_password_material_with_canonical_lengths()
    {
        var factory = new PasswordResetPasswordMaterialFactory(Options.Create(new LoginSettings
        {
            PasswordRetryLimit = 3,
            TwoAuthRetryLimit = 3,
            TwoFactorChallengePepper = "unit-test-two-factor-pepper",
            Argon2Iterations = 3,
            Argon2MemoryBytes = 67108864
        }));

        PasswordResetPasswordMaterial material = factory.CreatePasswordMaterial("new long passphrase");

        material.HashedPassword.Length.ShouldBe(AccountCryptoSizes.PasswordHashBytes);
        material.SaltOne.Length.ShouldBe(AccountCryptoSizes.SaltOneBytes);
        material.Siv.Length.ShouldBe(AccountCryptoSizes.SivBytes);
        material.Nonce.Length.ShouldBe(AccountCryptoSizes.NonceBytes);
    }

    [Fact]
    public void CreatePasswordMaterial_rejects_blank_password()
    {
        var factory = new PasswordResetPasswordMaterialFactory(Options.Create(new LoginSettings
        {
            PasswordRetryLimit = 3,
            TwoAuthRetryLimit = 3,
            TwoFactorChallengePepper = "unit-test-two-factor-pepper",
            Argon2Iterations = 3,
            Argon2MemoryBytes = 67108864
        }));

        Should.Throw<ArgumentException>(() => factory.CreatePasswordMaterial(" "));
    }
}
