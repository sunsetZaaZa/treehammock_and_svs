using Microsoft.Extensions.Options;

using treehammock.Rigging.Config;

namespace treehammock.Rigging.Security;

public interface IUserSecretHasher
{
    string HashUserSecret(string secret);
    bool VerifyUserSecret(string secret, string storedHash);
    Task<string> HashUserSecretAsync(string secret, CancellationToken cancellationToken = default)
        => Task.FromResult(HashUserSecret(secret));
    Task<bool> VerifyUserSecretAsync(string secret, string storedHash, CancellationToken cancellationToken = default)
        => Task.FromResult(VerifyUserSecret(secret, storedHash));
}

public sealed class Argon2idUserSecretHasher : IUserSecretHasher
{
    private readonly IPasswordWorkService _work;

    public Argon2idUserSecretHasher(IOptions<LoginSettings> loginSettings, IPasswordWorkService? work = null)
    {
        _work = work ?? PasswordWorkService.Default(loginSettings);
    }

    public string HashUserSecret(string secret)
    {
        if (string.IsNullOrWhiteSpace(secret))
        {
            throw new ArgumentException("A non-empty user secret is required.", nameof(secret));
        }

        return HashUserSecretAsync(secret).GetAwaiter().GetResult();
    }

    public bool VerifyUserSecret(string secret, string storedHash)
    {
        if (string.IsNullOrWhiteSpace(secret) || string.IsNullOrWhiteSpace(storedHash))
        {
            return false;
        }

        return VerifyUserSecretAsync(secret, storedHash).GetAwaiter().GetResult();
    }
    public Task<string> HashUserSecretAsync(string secret, CancellationToken cancellationToken = default)
        => _work.HashStringAsync(secret, cancellationToken);
    public Task<bool> VerifyUserSecretAsync(string secret, string storedHash, CancellationToken cancellationToken = default)
        => _work.VerifyStringAsync(storedHash, secret, cancellationToken);
}
