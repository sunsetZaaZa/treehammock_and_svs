using System.Security.Cryptography;
using System.Text;

namespace treehammock.Rigging.Authorization;

public static class TwoFactorChallengeCodeUtility
{
    public static string GenerateNumericCode(int digits = 6)
    {
        if (digits <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(digits), "Two-factor codes must contain at least one digit.");
        }

        int upperBound = (int)Math.Pow(10, digits);
        int value = RandomNumberGenerator.GetInt32(0, upperBound);
        return value.ToString($"D{digits}");
    }

    public static string Hash(string code, string? pepper = null)
    {
        if (string.IsNullOrWhiteSpace(code))
        {
            throw new ArgumentException("A two-factor code is required before it can be hashed.", nameof(code));
        }

        byte[] codeBytes = Encoding.UTF8.GetBytes(code);
        byte[] bytes;

        if (string.IsNullOrWhiteSpace(pepper))
        {
            bytes = SHA256.HashData(codeBytes);
        }
        else
        {
            byte[] pepperBytes = Encoding.UTF8.GetBytes(pepper);
            bytes = HMACSHA256.HashData(pepperBytes, codeBytes);
        }

        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}
