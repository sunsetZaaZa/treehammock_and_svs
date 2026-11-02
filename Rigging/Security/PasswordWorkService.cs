using System.ComponentModel.DataAnnotations;
using System.Text;
using Microsoft.Extensions.Options;
using treehammock.Rigging.Config;

namespace treehammock.Rigging.Security;

public sealed record PasswordVerification(bool Verified, byte[]? UpgradedHash = null);
public interface IPasswordWorkService
{
    Task<byte[]> HashBytesAsync(string secret, CancellationToken cancellationToken = default);
    Task<string> HashStringAsync(string secret, CancellationToken cancellationToken = default);
    Task<bool> VerifyBytesAsync(byte[] hash, string secret, CancellationToken cancellationToken = default);
    Task<bool> VerifyStringAsync(string hash, string secret, CancellationToken cancellationToken = default);
    Task<PasswordVerification> VerifyAndUpgradeAsync(byte[] hash, string secret, CancellationToken cancellationToken = default);
}
public sealed class PasswordWorkService : IPasswordWorkService
{
    private readonly LoginSettings _settings;
    private readonly PasswordWorkLimiter _limiter;
    public PasswordWorkService(IOptions<LoginSettings> settings, PasswordWorkLimiter limiter)
    {
        _settings = settings.Value; _limiter = limiter;
        // Validate cost contracts even for direct construction outside options startup.
        if (_settings.Argon2MemoryUsePer.HasValue || _settings.Argon2MemoryBytes < 67108864 || _settings.Argon2MemoryBytes % 1024 != 0
            || _settings.Argon2MemoryBytes > _settings.PasswordWork.MaxEncodedMemoryBytes
            || _settings.Argon2Iterations < 3 || _settings.Argon2Iterations > _settings.PasswordWork.MaxEncodedIterations)
            throw new ValidationException("Use explicit Argon2MemoryBytes >= 67108864 and iterations >= 3 within verification budgets.");
    }
    public static PasswordWorkService Default(IOptions<LoginSettings> settings)
    {
        var profile = settings.Value.PasswordWork;
        if (profile.MaxActiveOperations < 2 || profile.MemoryBudgetBytes < 134217728 || profile.CpuBudget < 4
            || profile.MaxQueuedOperations < 8 || profile.QueueTimeoutMilliseconds < 250)
            throw new ValidationException("Direct construction with narrower budgets must supply the shared password work service.");
        return new(settings, PasswordWorkLimiter.SharedDefault);
    }
    public async Task<byte[]> HashBytesAsync(string secret, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(secret)) throw new ArgumentException("A non-empty password is required.", nameof(secret));
        return await Run(() => Argon2idPasswordHashCodec.HashToStorageBytes(secret, _settings.Argon2Iterations, _settings.Argon2MemoryBytes),
            _settings.Argon2MemoryBytes, 1, cancellationToken);
    }
    public async Task<string> HashStringAsync(string secret, CancellationToken cancellationToken = default)
        => Encoding.UTF8.GetString(await HashBytesAsync(secret, cancellationToken)).TrimEnd('\0');
    public Task<bool> VerifyBytesAsync(byte[] hash, string secret, CancellationToken cancellationToken = default)
        => VerifyStringAsync(hash.Length <= AccountCryptoSizes.PasswordHashBytes ? Encoding.UTF8.GetString(hash) : "", secret, cancellationToken);
    public async Task<bool> VerifyStringAsync(string hash, string secret, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (string.IsNullOrWhiteSpace(secret) || !Argon2idPasswordHashCodec.TryReadCost(hash, _settings.PasswordWork, out var cost)) return false;
        return await Run(() => Argon2idPasswordHashCodec.VerifyStorageString(hash.TrimEnd('\0'), secret), cost!.MemoryBytes, cost.Parallelism, cancellationToken);
    }
    public async Task<PasswordVerification> VerifyAndUpgradeAsync(byte[] hash, string secret, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (hash.Length > AccountCryptoSizes.PasswordHashBytes || string.IsNullOrWhiteSpace(secret)) return new(false);
        string encoded = Encoding.UTF8.GetString(hash).TrimEnd('\0');
        if (!Argon2idPasswordHashCodec.TryReadCost(encoded, _settings.PasswordWork, out var cost)) return new(false);
        bool upgrade = cost!.Parallelism == 1 && (cost.MemoryBytes < _settings.Argon2MemoryBytes || cost.Iterations < _settings.Argon2Iterations);
        int memory = upgrade ? Math.Max(cost.MemoryBytes, _settings.Argon2MemoryBytes) : cost.MemoryBytes;
        int iterations = Math.Max(cost.Iterations, _settings.Argon2Iterations);
        return await Run(() =>
        {
            if (!Argon2idPasswordHashCodec.VerifyStorageString(encoded, secret)) return new PasswordVerification(false);
            return new PasswordVerification(true, upgrade ? Argon2idPasswordHashCodec.HashToStorageBytes(secret, iterations, memory) : null);
        }, memory, cost.Parallelism, cancellationToken);
    }
    private async Task<T> Run<T>(Func<T> work, int memory, int parallelism, CancellationToken caller)
    {
        try { return await _limiter.RunAsync(work, memory, parallelism, caller); }
        catch (InsufficientMemoryException) { throw new PasswordWorkBusyException(); }
    }
}
