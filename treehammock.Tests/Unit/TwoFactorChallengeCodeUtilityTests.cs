using Shouldly;

using treehammock.Rigging.Authorization;

namespace treehammock.Tests.Unit;

public class TwoFactorChallengeCodeUtilityTests
{
    [Fact]
    public void GenerateNumericCode_returns_fixed_width_digit_string()
    {
        string code = TwoFactorChallengeCodeUtility.GenerateNumericCode();

        code.Length.ShouldBe(6);
        code.ShouldAllBe(character => char.IsDigit(character));
    }

    [Fact]
    public void Hash_returns_sha256_hex_and_not_the_raw_code()
    {
        const string code = "123456";

        string hash = TwoFactorChallengeCodeUtility.Hash(code);

        hash.Length.ShouldBe(64);
        hash.ShouldNotBe(code);
        hash.ShouldBe(TwoFactorChallengeCodeUtility.Hash(code));
    }

    [Fact]
    public void Hash_uses_pepper_when_supplied()
    {
        const string code = "123456";

        string unpeppered = TwoFactorChallengeCodeUtility.Hash(code);
        string peppered = TwoFactorChallengeCodeUtility.Hash(code, "test-two-factor-pepper");

        peppered.Length.ShouldBe(64);
        peppered.ShouldNotBe(unpeppered);
        peppered.ShouldBe(TwoFactorChallengeCodeUtility.Hash(code, "test-two-factor-pepper"));
    }

}
