using System.Security.Cryptography;
using System.Text;

using Microsoft.Extensions.Options;
using NodaTime;

using treehammock.Rigging.Config;

namespace treehammock.Services;

public interface ITotpCodeVerifier
{
    TotpVerificationResult Verify(
        byte[] secret,
        string submittedCode,
        Instant now,
        long? lastUsedStep, TotpParameters parameters);
}

public sealed record TotpVerificationResult(
    bool Verified,
    long? AcceptedTimeStep,
    string Code)
{
    public const string VerifiedCode = "TOTP_VERIFIED";
    public const string InvalidShapeCode = "TOTP_INVALID_SHAPE";
    public const string InvalidSecretCode = "TOTP_INVALID_SECRET";
    public const string IncorrectCode = "TOTP_INCORRECT";
    public const string ReplayDetectedCode = "TOTP_REPLAY_DETECTED";

    public static TotpVerificationResult Success(long acceptedTimeStep)
    {
        return new TotpVerificationResult(true, acceptedTimeStep, VerifiedCode);
    }

    public static TotpVerificationResult Failed(string code)
    {
        return new TotpVerificationResult(false, null, code);
    }
}

public sealed class TotpCodeVerifier : ITotpCodeVerifier
{
    public TotpVerificationResult Verify(
        byte[] secret,
        string submittedCode,
        Instant now,
        long? lastUsedStep, TotpParameters parameters)
    {
        ArgumentNullException.ThrowIfNull(secret);
        parameters.Validate();

        string normalizedCode = (submittedCode ?? string.Empty).Trim();
        if (!IsValidSubmittedCode(normalizedCode, parameters.Digits))
        {
            return TotpVerificationResult.Failed(TotpVerificationResult.InvalidShapeCode);
        }

        if (secret.Length < TotpSettings.MinimumSecretBytes)
        {
            return TotpVerificationResult.Failed(TotpVerificationResult.InvalidSecretCode);
        }

        long currentTimeStep = now.ToUnixTimeSeconds() / parameters.PeriodSeconds;
        int skew = Math.Max(0, parameters.AllowedClockSkewSteps);

        for (long step = currentTimeStep - skew; step <= currentTimeStep + skew; step++)
        {
            if (step < 0)
            {
                continue;
            }

            if (lastUsedStep is not null && step <= lastUsedStep.Value)
            {
                continue;
            }

            string expectedCode = ComputeCode(secret, step, parameters.Digits, parameters.HashAlgorithm);
            if (FixedTimeEquals(normalizedCode, expectedCode))
            {
                return TotpVerificationResult.Success(step);
            }
        }

        return TotpVerificationResult.Failed(TotpVerificationResult.IncorrectCode);
    }

    internal static bool IsValidSubmittedCode(string? submittedCode, int digits)
    {
        if (string.IsNullOrWhiteSpace(submittedCode))
        {
            return false;
        }

        string normalizedCode = submittedCode.Trim();
        if (normalizedCode.Length != digits)
        {
            return false;
        }

        foreach (char current in normalizedCode)
        {
            if (current is < '0' or > '9')
            {
                return false;
            }
        }

        return true;
    }

    internal static string ComputeCode(byte[] secret, long timeStep, int digits, string hashAlgorithm)
    {
        byte[] counter = BitConverter.GetBytes(timeStep);
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(counter);
        }

        byte[] hmac = HashCounter(secret, counter, hashAlgorithm);
        int offset = hmac[^1] & 0x0f;
        int binaryCode = ((hmac[offset] & 0x7f) << 24)
            | ((hmac[offset + 1] & 0xff) << 16)
            | ((hmac[offset + 2] & 0xff) << 8)
            | (hmac[offset + 3] & 0xff);

        int modulus = PowerOfTen(digits);
        int code = binaryCode % modulus;
        return code.ToString($"D{digits}", System.Globalization.CultureInfo.InvariantCulture);
    }

    private static byte[] HashCounter(byte[] secret, byte[] counter, string hashAlgorithm)
    {
        return hashAlgorithm.ToUpperInvariant() switch
        {
            "SHA1" => HMACSHA1.HashData(secret, counter),
            "SHA256" => HMACSHA256.HashData(secret, counter),
            "SHA512" => HMACSHA512.HashData(secret, counter),
            _ => throw new InvalidOperationException("Unsupported TOTP hash algorithm.")
        };
    }

    private static bool FixedTimeEquals(string submittedCode, string expectedCode)
    {
        byte[] submittedBytes = Encoding.ASCII.GetBytes(submittedCode);
        byte[] expectedBytes = Encoding.ASCII.GetBytes(expectedCode);
        return CryptographicOperations.FixedTimeEquals(submittedBytes, expectedBytes);
    }

    private static int PowerOfTen(int digits)
    {
        int result = 1;
        for (int i = 0; i < digits; i++)
        {
            result *= 10;
        }

        return result;
    }
}
