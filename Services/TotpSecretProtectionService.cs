using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using treehammock.Rigging.Config;
namespace treehammock.Services;

public interface ITotpSecretProtector
{
    ProtectedTotpSecret Protect(byte[] secret, TotpEnrollmentContext context);
    byte[] Unprotect(ProtectedTotpSecret protectedSecret);
}
public sealed record ProtectedTotpSecret(byte[] Ciphertext, byte[] Nonce, byte[] Tag, int Version,
    string KeyId, TotpEnrollmentContext Context);

public sealed class TotpSecretProtector(IOptions<TotpSettings> settings) : ITotpSecretProtector
{
    public const int CurrentVersion = 2;
    public const int NonceSizeBytes = 12;
    public const int TagSizeBytes = 16;
    public ProtectedTotpSecret Protect(byte[] secret, TotpEnrollmentContext context)
    {
        ArgumentNullException.ThrowIfNull(secret); context.Validate();
        if (secret.Length is < 20 or > 64) throw new ArgumentException("TOTP secret must contain 20–64 bytes.", nameof(secret));
        string id = settings.Value.ActiveProtectionKeyId;
        byte[] key = ProtectionKey(id), nonce = RandomNumberGenerator.GetBytes(NonceSizeBytes), ciphertext = new byte[secret.Length], tag = new byte[TagSizeBytes];
        try
        {
            using var aes = new AesGcm(key, TagSizeBytes);
            aes.Encrypt(nonce, secret, ciphertext, tag, AssociatedData(id, context));
            return new(ciphertext, nonce, tag, CurrentVersion, id, context);
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }
    public byte[] Unprotect(ProtectedTotpSecret protectedSecret)
    {
        ArgumentNullException.ThrowIfNull(protectedSecret); protectedSecret.Context.Validate();
        if (protectedSecret.Version != CurrentVersion || protectedSecret.Nonce.Length != NonceSizeBytes ||
            protectedSecret.Tag.Length != TagSizeBytes || protectedSecret.Ciphertext.Length is < 20 or > 64)
            throw new InvalidOperationException("Unsupported or invalid protected TOTP envelope.");
        byte[] key = ProtectionKey(protectedSecret.KeyId), secret = new byte[protectedSecret.Ciphertext.Length];
        try
        {
            using var aes = new AesGcm(key, TagSizeBytes);
            aes.Decrypt(protectedSecret.Nonce, protectedSecret.Ciphertext, protectedSecret.Tag, secret, AssociatedData(protectedSecret.KeyId, protectedSecret.Context));
            return secret;
        }
        catch { CryptographicOperations.ZeroMemory(secret); throw; }
        finally { CryptographicOperations.ZeroMemory(key); }
    }
    private static byte[] AssociatedData(string keyId, TotpEnrollmentContext context) => Encoding.UTF8.GetBytes(
        JsonSerializer.Serialize(new { purpose = "treehammock:totp-secret:v2", keyId, account = context.AccountId.ToString("N"),
            enrollment = context.EnrollmentId.ToString("N"), algorithm = context.Parameters.HashAlgorithm, context.Parameters.Digits,
            context.Parameters.PeriodSeconds, context.Parameters.AllowedClockSkewSteps }));
    private byte[] ProtectionKey(string id)
    {
        if (!settings.Value.ProtectionKeys.TryGetValue(id, out string? encoded) || !TotpSettings.TryDecodeProtectionKey(encoded, out byte[] key))
            throw new InvalidOperationException("TOTP protection key is missing or invalid; explicit key recovery is required.");
        return key;
    }
}
