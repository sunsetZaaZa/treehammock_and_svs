using Microsoft.AspNetCore.WebUtilities;
using System.Security.Cryptography;

namespace treehammock.Rigging.Security;

public static class AccountVerificationTokenUtility
{
    public const int DefaultTokenBytes = 32;

    public static string GenerateToken(int bytes = DefaultTokenBytes)
    {
        if (bytes < 16)
        {
            throw new ArgumentOutOfRangeException(nameof(bytes), "Verification tokens must use at least 128 bits of entropy.");
        }

        return WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(bytes));
    }

    public static string EncodeBase64Url(byte[] value)
    {
        if (value == null || value.Length == 0)
        {
            throw new ArgumentException("A non-empty byte array is required.", nameof(value));
        }

        return WebEncoders.Base64UrlEncode(value);
    }

    public static string HashToken(string token) => SecretHashUtility.HashLookupToken(token);
}
