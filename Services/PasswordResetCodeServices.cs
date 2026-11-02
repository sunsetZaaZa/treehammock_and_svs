using System.Security.Cryptography;
using System.Text;

using Microsoft.Extensions.Options;

using treehammock.Rigging.Config;

namespace treehammock.Services;

public interface IPasswordResetCodeGenerator
{
    string GenerateKeyCode();
}

public interface IPasswordResetCodeHasher
{
    int HashVersion { get; }

    string HashCode(Guid resetId, string code);

    bool VerifyCode(Guid resetId, string code, string storedHash);
}

public sealed class PasswordResetCodeGenerator : IPasswordResetCodeGenerator
{
    private readonly IOptions<PasswordResetSettings> _settings;

    public PasswordResetCodeGenerator(IOptions<PasswordResetSettings> settings)
    {
        _settings = settings;
    }

    public string GenerateKeyCode()
    {
        int length = _settings.Value.CodeLength;
        if (length < PasswordResetSettings.MinimumCodeLength || length > PasswordResetSettings.MaximumCodeLength)
        {
            throw new InvalidOperationException(
                $"Password reset code length must be between {PasswordResetSettings.MinimumCodeLength} and {PasswordResetSettings.MaximumCodeLength} digits.");
        }

        Span<char> digits = stackalloc char[length];
        for (int index = 0; index < digits.Length; index++)
        {
            digits[index] = (char)('0' + RandomNumberGenerator.GetInt32(0, 10));
        }

        return new string(digits);
    }
}

public sealed class PasswordResetCodeHasher : IPasswordResetCodeHasher
{
    public const int CurrentHashVersion = 1;

    private readonly IOptions<PasswordResetSettings> _settings;

    public PasswordResetCodeHasher(IOptions<PasswordResetSettings> settings)
    {
        _settings = settings;
    }

    public int HashVersion => CurrentHashVersion;

    public string HashCode(Guid resetId, string code)
    {
        if (resetId == Guid.Empty)
        {
            throw new ArgumentException("A non-empty reset id is required before a reset code can be hashed.", nameof(resetId));
        }

        if (string.IsNullOrWhiteSpace(code))
        {
            throw new ArgumentException("A non-empty password reset code is required before it can be hashed.", nameof(code));
        }

        string pepper = _settings.Value.CodeHashPepper;
        if (string.IsNullOrWhiteSpace(pepper))
        {
            throw new InvalidOperationException("PasswordResetSettings:CodeHashPepper is required before password reset codes can be hashed.");
        }

        byte[] keyBytes = Encoding.UTF8.GetBytes(pepper);
        byte[] messageBytes = Encoding.UTF8.GetBytes($"pwdreset:v{CurrentHashVersion}:{resetId:N}:{code.Trim()}");
        byte[] hash = HMACSHA256.HashData(keyBytes, messageBytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    public bool VerifyCode(Guid resetId, string code, string storedHash)
    {
        if (string.IsNullOrWhiteSpace(storedHash))
        {
            return false;
        }

        string computedHash;
        try
        {
            computedHash = HashCode(resetId, code);
        }
        catch (ArgumentException)
        {
            return false;
        }

        byte[] computedBytes = Encoding.ASCII.GetBytes(computedHash);
        byte[] storedBytes = Encoding.ASCII.GetBytes(storedHash.Trim().ToLowerInvariant());

        return computedBytes.Length == storedBytes.Length
            && CryptographicOperations.FixedTimeEquals(computedBytes, storedBytes);
    }
}
