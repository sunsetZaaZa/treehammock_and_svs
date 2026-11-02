using Microsoft.Extensions.Options;
using Shouldly;

using treehammock.Rigging.Config;
using treehammock.Rigging.Security;

namespace treehammock.Tests.Unit;

public class SecretHashUtilityTests
{
    [Fact]
    public void HashLookupToken_returns_stable_lowercase_sha256_hex_hash()
    {
        string first = SecretHashUtility.HashLookupToken("secret-token");
        string second = SecretHashUtility.HashLookupToken("secret-token");

        first.ShouldBe(second);
        first.Length.ShouldBe(64);
        first.ShouldBe(first.ToLowerInvariant());
        first.ShouldNotBe("secret-token");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void HashOptionalLookupToken_returns_null_for_empty_optional_secrets(string? value)
    {
        SecretHashUtility.HashOptionalLookupToken(value).ShouldBeNull();
    }

    [Fact]
    public void HashOptionalLookupToken_hashes_non_empty_optional_secrets()
    {
        SecretHashUtility.HashOptionalLookupToken("lookup-token").ShouldBe(SecretHashUtility.HashLookupToken("lookup-token"));
    }

    [Fact]
    public void Argon2id_user_secret_hasher_verifies_correct_secret_and_rejects_wrong_secret()
    {
        IUserSecretHasher hasher = CreateHasher();

        string storedHash = hasher.HashUserSecret("delete me");

        storedHash.ShouldNotBeNullOrWhiteSpace();
        storedHash.ShouldNotBe("delete me");
        storedHash.ShouldNotBe(SecretHashUtility.HashLookupToken("delete me"));
        hasher.VerifyUserSecret("delete me", storedHash).ShouldBeTrue();
        hasher.VerifyUserSecret("wrong secret", storedHash).ShouldBeFalse();
    }

    private static IUserSecretHasher CreateHasher()
    {
        return new Argon2idUserSecretHasher(Options.Create(new LoginSettings
        {
            PasswordRetryLimit = 3,
            TwoAuthRetryLimit = 3,
            Argon2Iterations = 3,
            Argon2MemoryBytes = 67108864,
            TwoFactorChallengePepper = "0123456789abcdef"
        }));
    }
}
