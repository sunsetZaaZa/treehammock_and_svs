using System.Text;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using treehammock.Rigging.Config;

using Geralt;

namespace treehammock.Rigging.Security;

internal static class Argon2idPasswordHashCodec
{
    public sealed record Cost(int MemoryBytes, int Iterations, int Parallelism);
    private static readonly Regex Phc = new("^\\$argon2id\\$v=19\\$m=([0-9]{1,9}),t=([0-9]{1,2}),p=([0-9])\\$([A-Za-z0-9+/]{22})\\$([A-Za-z0-9+/]{43})$", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    public static bool TryReadCost(string hash, PasswordWorkSettings bounds, out Cost? cost)
    {
        cost = null;
        if (hash.Length > AccountCryptoSizes.PasswordHashBytes) return false;
        var match = Phc.Match(hash.TrimEnd('\0'));
        if (!match.Success || !int.TryParse(match.Groups[1].Value, out int kib)
            || !int.TryParse(match.Groups[2].Value, out int iterations)
            || !int.TryParse(match.Groups[3].Value, out int parallelism)) return false;
        long memory = (long)kib * 1024;
        if (memory < 8192 || memory > bounds.MaxEncodedMemoryBytes || iterations < 1 || iterations > bounds.MaxEncodedIterations
            || parallelism < 1 || parallelism > bounds.MaxEncodedParallelism || kib < 8 * parallelism) return false;
        // Require canonical unpadded Base64; malformed encodings never reach native work.
        try
        {
            foreach (int index in new[] { 4, 5 })
            {
                string value = match.Groups[index].Value;
                byte[] bytes = Convert.FromBase64String(value.PadRight((value.Length + 3) / 4 * 4, '='));
                if (Convert.ToBase64String(bytes).TrimEnd('=') != value) return false;
            }
        }
        catch (FormatException) { return false; }
        cost = new((int)memory, iterations, parallelism); return true;
    }
    public static byte[] HashToStorageBytes(string secret, int iterations, int memoryBytes)
    {
        if (iterations is < 1 or > 10 || memoryBytes is < 8192 or > 134217728)
            throw new ArgumentOutOfRangeException(nameof(memoryBytes));
        char[] hash = new char[AccountCryptoSizes.PasswordHashBytes];
        byte[] password = Encoding.UTF8.GetBytes(secret);
        try { Argon2id.ComputeHash(hash, password, iterations, memoryBytes); return Encoding.UTF8.GetBytes(hash); }
        finally { CryptographicOperations.ZeroMemory(password); Array.Clear(hash); }
    }
    public static string HashToStorageString(string secret, int iterations, int memoryBytes)
        => Encoding.UTF8.GetString(HashToStorageBytes(secret, iterations, memoryBytes)).TrimEnd('\0');
    public static bool VerifyStorageBytes(byte[] storedHash, string secret)
    {
        if (storedHash.Length == 0 || string.IsNullOrEmpty(secret))
        {
            return false;
        }

        return storedHash.Length <= AccountCryptoSizes.PasswordHashBytes && VerifyStorageString(Encoding.UTF8.GetString(storedHash), secret);
    }

    public static bool VerifyStorageString(string storedHash, string secret)
    {
        if (string.IsNullOrWhiteSpace(storedHash) || string.IsNullOrEmpty(secret))
        {
            return false;
        }

        if (!TryReadCost(storedHash, new(), out _)) return false;
        byte[] password = Encoding.UTF8.GetBytes(secret);
        try { return Argon2id.VerifyHash(storedHash.TrimEnd('\0').AsSpan(), password); }
        catch (Exception ex) when (ex is ArgumentException or FormatException) { return false; }
        finally { CryptographicOperations.ZeroMemory(password); }
    }
}
