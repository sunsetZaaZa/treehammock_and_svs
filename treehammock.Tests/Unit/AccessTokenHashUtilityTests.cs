using System.Security.Cryptography;
using System.Text;
using Shouldly;

using treehammock.Rigging.Authorization;

namespace treehammock.Tests.Unit;

public class AccessTokenHashUtilityTests
{
    [Fact]
    public void Hash_returns_sha256_hex_digest_of_access_token()
    {
        const string accessToken = "active-access-token";
        string expected = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(accessToken)));

        string hash = AccessTokenHashUtility.Hash(accessToken);

        hash.ShouldBe(expected);
        hash.Length.ShouldBe(64);
    }
}
