using System.Security.Cryptography;
using System.Text;

namespace treehammock.Rigging.Security;

public static class SecretHashUtility
{
    public static string HashLookupToken(string token)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            throw new ArgumentException("A non-empty secret token is required.", nameof(token));
        }

        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(token));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    public static string? HashOptionalLookupToken(string? token)
    {
        return string.IsNullOrWhiteSpace(token)
            ? null
            : HashLookupToken(token);
    }

    public static string HashToken(string token) => HashLookupToken(token);

    public static string? HashOptionalToken(string? token) => HashOptionalLookupToken(token);
}
