using System.Security.Cryptography;
using Microsoft.Extensions.Options;

using treehammock.Rigging.Config;
using treehammock.Rigging.Security;

namespace treehammock.Services;

public interface IPasswordResetPasswordMaterialFactory
{
    PasswordResetPasswordMaterial CreatePasswordMaterial(string password);
    Task<PasswordResetPasswordMaterial> CreatePasswordMaterialAsync(string password, CancellationToken cancellationToken = default)
        => Task.FromResult(CreatePasswordMaterial(password));
}

public sealed record PasswordResetPasswordMaterial(
    byte[] HashedPassword,
    byte[] SaltOne,
    byte[] Siv,
    byte[] Nonce);

public sealed class PasswordResetPasswordMaterialFactory : IPasswordResetPasswordMaterialFactory
{
    private const int SaltOffset = 0;
    private const int SivOffset = SaltOffset + AccountCryptoSizes.SaltOneBytes;
    private const int NonceOffset = SivOffset + AccountCryptoSizes.SivBytes;
    private const int RandomMaterialBytes = AccountCryptoSizes.SaltOneBytes + AccountCryptoSizes.SivBytes + AccountCryptoSizes.NonceBytes;

    private readonly IPasswordWorkService _work;

    public PasswordResetPasswordMaterialFactory(IOptions<LoginSettings> loginSettings, IPasswordWorkService? work = null)
    {
        _work = work ?? PasswordWorkService.Default(loginSettings);
    }

    public PasswordResetPasswordMaterial CreatePasswordMaterial(string password)
        => CreatePasswordMaterialAsync(password).GetAwaiter().GetResult();

    public async Task<PasswordResetPasswordMaterial> CreatePasswordMaterialAsync(string password, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(password))
        {
            throw new ArgumentException("A non-empty password is required.", nameof(password));
        }

        byte[] passwordHash = await _work.HashBytesAsync(password, cancellationToken);

        byte[] randomMaterial = RandomNumberGenerator.GetBytes(RandomMaterialBytes);

        return new PasswordResetPasswordMaterial(
            passwordHash,
            Slice(randomMaterial, AccountCryptoSizes.SaltOneBytes, SaltOffset),
            Slice(randomMaterial, AccountCryptoSizes.SivBytes, SivOffset),
            Slice(randomMaterial, AccountCryptoSizes.NonceBytes, NonceOffset));
    }

    private static byte[] Slice(byte[] source, int length, int offset)
    {
        byte[] result = new byte[length];
        Buffer.BlockCopy(source, offset, result, 0, length);
        return result;
    }
}
