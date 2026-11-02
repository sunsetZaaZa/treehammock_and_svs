using NpgsqlTypes;
using Shouldly;

using treehammock.Repos;
using treehammock.Rigging.Security;

namespace treehammock.Tests.Unit;

public class AccountCryptoSizesTests
{
    [Fact]
    public void Account_crypto_sizes_are_single_source_of_truth()
    {
        AccountCryptoSizes.PasswordHashBytes.ShouldBe(128);
        AccountCryptoSizes.WebKeyBytes.ShouldBe(128);
        AccountCryptoSizes.SaltOneBytes.ShouldBe(64);
        AccountCryptoSizes.SivBytes.ShouldBe(32);
        AccountCryptoSizes.NonceBytes.ShouldBe(16);
        AccountCryptoSizes.WebKeyBase64UrlLength.ShouldBe(171);
    }

    [Fact]
    public void Account_crypto_storage_contract_matches_database_types()
    {
        AccountCryptoSizes.HashedPasswordStorage.ShouldBe("bytea");
        AccountCryptoSizes.WebKeyStorage.ShouldBe("text/base64url");
        AccountCryptoSizes.SaltOneStorage.ShouldBe("bytea");
        AccountCryptoSizes.SivStorage.ShouldBe("bytea");
        AccountCryptoSizes.NonceStorage.ShouldBe("bytea");
        AccountCryptoSizes.RefreshTokenStorage.ShouldBe("bytea");
        AccountCryptoSizes.AccessTokenHashStorage.ShouldBe("text/sha256-hex");

        AccountRepo.HashedPasswordDbType.ShouldBe(NpgsqlDbType.Bytea);
        AccountRepo.WebKeyDbType.ShouldBe(NpgsqlDbType.Text);
        AccountRepo.SaltOneDbType.ShouldBe(NpgsqlDbType.Bytea);
        AccountRepo.SivDbType.ShouldBe(NpgsqlDbType.Bytea);
        AccountRepo.NonceDbType.ShouldBe(NpgsqlDbType.Bytea);
        AccountRepo.RefreshTokenDbType.ShouldBe(NpgsqlDbType.Bytea);
        SessionRepo.RefreshTokenDbType.ShouldBe(NpgsqlDbType.Bytea);
        SessionRepo.AccessTokenHashDbType.ShouldBe(NpgsqlDbType.Text);
    }
}
