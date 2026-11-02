using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Shouldly;

using treehammock.Rigging.Config;
using treehammock.Services;

namespace treehammock.Tests.Unit;

public class TotpSecretProtectionServiceTests
{
    private static readonly TotpEnrollmentContext Context = new(Guid.NewGuid(), Guid.NewGuid(), new("SHA1",6,30,1));
    [Fact]
    public void Protect_returns_ciphertext_nonce_tag_and_version_without_plaintext_storage()
    {
        var protector = new TotpSecretProtector(Options.Create(Settings()));
        byte[] secret = RandomNumberGenerator.GetBytes(20);

        ProtectedTotpSecret protectedSecret = protector.Protect(secret, Context);

        protectedSecret.Version.ShouldBe(TotpSecretProtector.CurrentVersion);
        protectedSecret.Nonce.Length.ShouldBe(TotpSecretProtector.NonceSizeBytes);
        protectedSecret.Tag.Length.ShouldBe(TotpSecretProtector.TagSizeBytes);
        protectedSecret.Ciphertext.Length.ShouldBe(secret.Length);
        protectedSecret.Ciphertext.ShouldNotBe(secret);
    }

    [Fact]
    public void Unprotect_round_trips_secret()
    {
        var protector = new TotpSecretProtector(Options.Create(Settings()));
        byte[] secret = RandomNumberGenerator.GetBytes(20);

        ProtectedTotpSecret protectedSecret = protector.Protect(secret, Context);
        byte[] unprotected = protector.Unprotect(protectedSecret);

        unprotected.ShouldBe(secret);
    }

    [Fact]
    public void Unprotect_fails_closed_when_ciphertext_is_tampered()
    {
        var protector = new TotpSecretProtector(Options.Create(Settings()));
        ProtectedTotpSecret protectedSecret = protector.Protect(RandomNumberGenerator.GetBytes(20), Context);
        protectedSecret.Ciphertext[0] ^= 0x01;

        Should.Throw<CryptographicException>(() => protector.Unprotect(protectedSecret));
    }

    [Fact]
    public void Unprotect_fails_closed_when_secret_version_is_unknown()
    {
        var protector = new TotpSecretProtector(Options.Create(Settings()));
        ProtectedTotpSecret protectedSecret = protector.Protect(RandomNumberGenerator.GetBytes(20), Context);
        var wrongVersion = protectedSecret with { Version = 999 };

        Should.Throw<InvalidOperationException>(() => protector.Unprotect(wrongVersion));
    }

    [Fact]
    public void Protector_requires_valid_base64_32_byte_key()
    {
        var protector = new TotpSecretProtector(Options.Create(Settings(secretProtectionKey: "not-base64")));

        Should.Throw<InvalidOperationException>(() => protector.Protect(RandomNumberGenerator.GetBytes(20), Context));
    }

    private static TotpSettings Settings(string? secretProtectionKey = null)
    {
        return new TotpSettings
        {
            Issuer = "Treehammock",
            Digits = 6,
            PeriodSeconds = 30,
            AllowedClockSkewSteps = 1,
            HashAlgorithm = "SHA1",
            SecretBytes = 20,
            ActiveProtectionKeyId = "test", ProtectionKeys = new() { ["test"] = secretProtectionKey ?? Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)) }
        };
    }
}
