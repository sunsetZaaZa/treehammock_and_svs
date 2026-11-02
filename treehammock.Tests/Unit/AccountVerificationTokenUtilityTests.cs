using Shouldly;

using treehammock.Rigging.Security;

namespace treehammock.Tests.Unit;

public class AccountVerificationTokenUtilityTests
{
    [Fact]
    public void GenerateToken_returns_url_safe_random_token()
    {
        string token = AccountVerificationTokenUtility.GenerateToken();

        token.ShouldNotBeNullOrWhiteSpace();
        token.ShouldNotContain("+");
        token.ShouldNotContain("/");
        token.ShouldNotContain("=");
    }

    [Fact]
    public void EncodeBase64Url_preserves_binary_material_without_utf8_coercion()
    {
        byte[] bytes = [0, 255, 1, 128, 64, 32];

        string encoded = AccountVerificationTokenUtility.EncodeBase64Url(bytes);

        encoded.ShouldNotContain("\0");
        encoded.ShouldNotContain("+");
        encoded.ShouldNotContain("/");
        encoded.ShouldNotContain("=");
    }

    [Fact]
    public void HashToken_returns_stable_sha256_hex_hash()
    {
        string first = AccountVerificationTokenUtility.HashToken("abc123");
        string second = AccountVerificationTokenUtility.HashToken("abc123");

        first.ShouldBe(second);
        first.Length.ShouldBe(64);
    }
}
