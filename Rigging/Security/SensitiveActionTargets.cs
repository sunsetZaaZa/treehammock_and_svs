using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using treehammock.RiggingSupport.Enum;
namespace treehammock.Rigging.Security;

public static class SensitiveActionTargets
{
    public static bool Supported(SensitiveActionPurpose purpose) => purpose is SensitiveActionPurpose.TWO_FACTOR_AUTHENTICATOR_SETUP or SensitiveActionPurpose.TWO_FACTOR_METHOD_REMOVE or SensitiveActionPurpose.TWO_FACTOR_EMAIL_ENROLL or SensitiveActionPurpose.TWO_FACTOR_SMS_ENROLL or SensitiveActionPurpose.ACCOUNT_EMAIL_CHANGE or SensitiveActionPurpose.ACCOUNT_DELETE;
    public static string AuthenticatorSetup(string? label, bool required, TotpProviderType provider, Guid? expectedEnrollmentId = null, long? expectedVersion = null)
        => "setup:" + JsonSerializer.Serialize(new object[] { string.IsNullOrWhiteSpace(label) ? "authenticator-app" : label.Trim(), required, (int)provider, expectedEnrollmentId, expectedVersion });
    public static string DeliverySetup(TwoFactorAuthMethod method, string contact, short? countryCode, bool required,
        Guid? expectedEnrollmentId = null, long? expectedVersion = null)
        => "enroll:" + JsonSerializer.Serialize(new object[] { (int)method,
            method == TwoFactorAuthMethod.EMAIL ? contact.Trim().ToLowerInvariant() : contact.Trim(),
            countryCode, required, expectedEnrollmentId, expectedVersion });
    public static string EmailChange(string email) => "email:" + email.Trim().ToLowerInvariant();
    public static string AccountDelete(string? passPhrase) => string.IsNullOrWhiteSpace(passPhrase) ? "delete:one-time" : "delete:passphrase";
    public static string RemoveMethod(TwoFactorAuthMethod method) => "factor:" + (int)method;
    public static string DefaultSetup => AuthenticatorSetup(null, true, TotpProviderType.LOCAL_RFC6238);
    public static string Hash(SensitiveActionPurpose purpose, string target, string pepper)
    {
        if (!Supported(purpose) || target.Length is < 1 or > 1024 || pepper.Length < 16) throw new ArgumentException("A bounded purpose/target and shared pepper are required.");
        byte[] key = Encoding.UTF8.GetBytes(pepper);
        try { return Convert.ToHexString(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes("treehammock:sensitive-target:v1:" + (int)purpose + ":" + target))); }
        finally { CryptographicOperations.ZeroMemory(key); }
    }
}
