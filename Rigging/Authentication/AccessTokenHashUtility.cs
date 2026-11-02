using System.Security.Cryptography;
using System.Text;

namespace treehammock.Rigging.Authorization;

internal static class AccessTokenHashUtility
{
    public static string Hash(string accessToken)
    {
        if (string.IsNullOrWhiteSpace(accessToken))
        {
            throw new ArgumentException("Access token is required before it can be hashed.", nameof(accessToken));
        }

        byte[] digest = SHA256.HashData(Encoding.UTF8.GetBytes(accessToken));
        return Convert.ToHexString(digest);
    }
}
