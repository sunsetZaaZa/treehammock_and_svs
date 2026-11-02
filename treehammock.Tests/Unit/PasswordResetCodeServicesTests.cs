using Microsoft.Extensions.Options;
using Shouldly;

using treehammock.Rigging.Config;
using treehammock.Services;

namespace treehammock.Tests.Unit;

public class PasswordResetCodeServicesTests
{
    [Fact]
    public void Generator_uses_configured_digit_length()
    {
        var generator = new PasswordResetCodeGenerator(Options.Create(Settings(codeLength: 10)));

        string code = generator.GenerateKeyCode();

        code.Length.ShouldBe(10);
        code.ShouldAllBe(character => char.IsDigit(character));
    }

    [Theory]
    [InlineData(5)]
    [InlineData(17)]
    public void Generator_rejects_invalid_runtime_code_length(int codeLength)
    {
        var generator = new PasswordResetCodeGenerator(Options.Create(Settings(codeLength: codeLength)));

        var exception = Should.Throw<InvalidOperationException>(() => generator.GenerateKeyCode());

        exception.Message.ShouldContain("Password reset code length");
    }

    [Fact]
    public void Hasher_returns_stable_hmac_hex_hash_without_storing_plaintext_code()
    {
        var hasher = new PasswordResetCodeHasher(Options.Create(Settings()));
        var resetId = Guid.NewGuid();

        string first = hasher.HashCode(resetId, "49382710");
        string second = hasher.HashCode(resetId, "49382710");

        first.ShouldBe(second);
        first.Length.ShouldBe(64);
        first.ShouldBe(first.ToLowerInvariant());
        first.ShouldNotContain("49382710");
        hasher.HashVersion.ShouldBe(PasswordResetCodeHasher.CurrentHashVersion);
    }

    [Fact]
    public void Hasher_binds_hash_to_reset_id()
    {
        var hasher = new PasswordResetCodeHasher(Options.Create(Settings()));

        string first = hasher.HashCode(Guid.NewGuid(), "49382710");
        string second = hasher.HashCode(Guid.NewGuid(), "49382710");

        first.ShouldNotBe(second);
    }

    [Fact]
    public void Hasher_binds_hash_to_configured_pepper()
    {
        var resetId = Guid.NewGuid();
        var firstHasher = new PasswordResetCodeHasher(Options.Create(Settings(pepper: "test-password-reset-code-pepper-a")));
        var secondHasher = new PasswordResetCodeHasher(Options.Create(Settings(pepper: "test-password-reset-code-pepper-b")));

        string first = firstHasher.HashCode(resetId, "49382710");
        string second = secondHasher.HashCode(resetId, "49382710");

        first.ShouldNotBe(second);
    }

    [Fact]
    public void VerifyCode_accepts_correct_code_and_rejects_wrong_code()
    {
        var hasher = new PasswordResetCodeHasher(Options.Create(Settings()));
        var resetId = Guid.NewGuid();
        string storedHash = hasher.HashCode(resetId, "49382710");

        hasher.VerifyCode(resetId, "49382710", storedHash).ShouldBeTrue();
        hasher.VerifyCode(resetId, "00000000", storedHash).ShouldBeFalse();
        hasher.VerifyCode(Guid.NewGuid(), "49382710", storedHash).ShouldBeFalse();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void VerifyCode_rejects_missing_stored_hash(string? storedHash)
    {
        var hasher = new PasswordResetCodeHasher(Options.Create(Settings()));

        hasher.VerifyCode(Guid.NewGuid(), "49382710", storedHash!).ShouldBeFalse();
    }

    [Fact]
    public void HashCode_rejects_empty_reset_id()
    {
        var hasher = new PasswordResetCodeHasher(Options.Create(Settings()));

        Should.Throw<ArgumentException>(() => hasher.HashCode(Guid.Empty, "49382710"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void HashCode_rejects_missing_code(string? code)
    {
        var hasher = new PasswordResetCodeHasher(Options.Create(Settings()));

        Should.Throw<ArgumentException>(() => hasher.HashCode(Guid.NewGuid(), code!));
    }

    private static PasswordResetSettings Settings(int codeLength = 8, string pepper = "test-password-reset-code-pepper")
    {
        return new PasswordResetSettings
        {
            CodeLength = codeLength,
            CodeHashPepper = pepper,
            ExpirationMinutes = 2,
            MaxAttempts = 5,
            RequestCooldownSeconds = 60,
            DailyRequestLimitPerAccount = 5,
            DailyRequestLimitPerDestination = 5,
            DailyRequestLimitPerIp = 20
        };
    }
}
