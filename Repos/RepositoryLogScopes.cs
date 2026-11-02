using System.Security.Cryptography;
using System.Text;

using NodaTime;

using treehammock.RiggingSupport.Actions.Account;
using treehammock.RiggingSupport.Enum;

namespace treehammock.Repos;

internal sealed record RepositorySensitiveValueLogScope(string ValueKind, int ValueLength, string ValueFingerprint)
{
    public static RepositorySensitiveValueLogScope From(string? value, string valueKind)
    {
        string trimmed = value?.Trim() ?? string.Empty;

        return new RepositorySensitiveValueLogScope(
            valueKind,
            trimmed.Length,
            Fingerprint(trimmed, valueKind));
    }

    private static string Fingerprint(string value, string valueKind)
    {
        if (value.Length == 0)
        {
            return "none";
        }

        string normalized = $"{valueKind}:{value}".ToLowerInvariant();
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(normalized));
        return Convert.ToHexString(hash, 0, 6).ToLowerInvariant();
    }
}

internal static class RepositoryLogScopes
{
    public static RepositorySensitiveValueLogScope Identifier(string? identifier) =>
        RepositorySensitiveValueLogScope.From(identifier, ClassifyIdentifier(identifier));

    public static RepositorySensitiveValueLogScope EmailAddress(string? emailAddress) =>
        RepositorySensitiveValueLogScope.From(emailAddress, "email");

    public static RepositorySensitiveValueLogScope Username(string? username) =>
        RepositorySensitiveValueLogScope.From(username, "username");

    public static RepositorySensitiveValueLogScope TokenHash(string? tokenHash) =>
        RepositorySensitiveValueLogScope.From(tokenHash, "token_hash");

    public static RepositorySensitiveValueLogScope VerificationTokenHash(string? tokenHash) =>
        RepositorySensitiveValueLogScope.From(tokenHash, "verification_token_hash");

    public static object AccountSetup(AccountSetupAction step, Guid accountId, string? emailAddress, string? username) =>
        new
        {
            step,
            accountId,
            emailAddressMetadata = EmailAddress(emailAddress),
            usernameMetadata = Username(username)
        };

    public static object EmailAddressScope(string? emailAddress) =>
        new { emailAddressMetadata = EmailAddress(emailAddress) };

    public static object IdentifierLookup(string? identifier, Instant now) =>
        new { identifierMetadata = Identifier(identifier), now };

    public static object VerificationTokenHashScope(string? tokenHash) =>
        new { tokenHashMetadata = VerificationTokenHash(tokenHash) };

    public static object AccessTokenHashScope(string? tokenHash) =>
        new { accessTokenHashMetadata = TokenHash(tokenHash) };

    public static object AccessTokenHashExpiration(string? tokenHash, Instant expiration) =>
        new { accessTokenHashMetadata = TokenHash(tokenHash), expiration };

    public static object AccountUsername(Guid accountId, string? username) =>
        new { accountId, usernameMetadata = Username(username) };

    public static object AccountEmailAddress(Guid accountId, string? emailAddress) =>
        new { accountId, emailAddressMetadata = EmailAddress(emailAddress) };

    public static object AccountTokenHash(Guid accountId, string? tokenHash) =>
        new { accountId, tokenHashMetadata = TokenHash(tokenHash) };

    public static object AccountTokenHashes(Guid accountId, string? oldTokenHash, string? newTokenHash) =>
        new
        {
            accountId,
            oldTokenHashMetadata = TokenHash(oldTokenHash),
            newTokenHashMetadata = TokenHash(newTokenHash)
        };

    public static object ActivationEmail(Guid accountId, string? emailAddress, Instant createdOn, Instant closeOff, ActivationStatus status) =>
        new { accountId, emailAddressMetadata = EmailAddress(emailAddress), createdOn, closeOff, status };

    public static object ActivationVerificationEmail(Guid accountId, string? emailAddress, ushort position, ushort upperLimit) =>
        new { accountId, emailAddressMetadata = EmailAddress(emailAddress), position, upperLimit };

    private static string ClassifyIdentifier(string? identifier)
    {
        string trimmed = identifier?.Trim() ?? string.Empty;

        if (trimmed.Length == 0)
        {
            return "blank";
        }

        if (trimmed.Contains('@', StringComparison.Ordinal))
        {
            return "email";
        }

        bool containsDigit = false;
        bool phoneLike = true;

        foreach (char ch in trimmed)
        {
            if (char.IsDigit(ch))
            {
                containsDigit = true;
                continue;
            }

            if (ch is '+' or '-' or '(' or ')' or ' ' or '.')
            {
                continue;
            }

            phoneLike = false;
            break;
        }

        return phoneLike && containsDigit ? "phone" : "username";
    }
}
