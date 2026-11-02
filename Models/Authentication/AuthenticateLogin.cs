using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;

using NodaTime;

using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;

namespace treehammock.Models.Authentication;

public class AuthenticateLogin : IValidatableObject
{
    public const int MaxUsernameLength = 128;
    public const int MaxEmailAddressLength = 1024;
    public const int MaxPasswordLength = 512;

    public AuthenticateLogin()
    {
    }

    [SetsRequiredMembers]
    public AuthenticateLogin(string emailAddress, string password)
    {
        (this.emailAddress, this.username, this.password) = (emailAddress, null, password);
    }

    [SetsRequiredMembers]
    public AuthenticateLogin(string emailAddress, string username, string password)
    {
        (this.emailAddress, this.username, this.password) = (emailAddress, username, password);
    }

    [StringLength(MaxUsernameLength)]
    public string? username { get; set; } = null;

    [EmailAddress]
    [StringLength(MaxEmailAddressLength)]
    public string? emailAddress { get; set; }

    [Required(AllowEmptyStrings = false)]
    [StringLength(MaxPasswordLength)]
    public string password { get; set; } = string.Empty;

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        bool hasEmail = !string.IsNullOrWhiteSpace(emailAddress);
        bool hasUsername = !string.IsNullOrWhiteSpace(username);

        if (!hasEmail && !hasUsername)
        {
            yield return new ValidationResult(
                "Either emailAddress or username is required.",
                new[] { nameof(emailAddress), nameof(username) });
        }
    }
}


public class AuthenticateResponse
{
    [SetsRequiredMembers]
    public AuthenticateResponse(
        HttpMessage result,
        string? accessToken = null,
        List<TwoFactorAuthMethod>? twoFactorAuthMethods = null,
        Duration? lockoutDuration = null,
        string? twoFactorAccessToken = null,
        List<TwoFactorAuthConfiguration>? availableTwoFactorAuthConfigurations = null)
    {
        (this.result, this.accessToken, this.twoFactorAuthMethods, this.lockoutDuration, this.twoFactorAccessToken, this.availableTwoFactorAuthConfigurations) =
            (result, accessToken, twoFactorAuthMethods, lockoutDuration, twoFactorAccessToken, availableTwoFactorAuthConfigurations);
    }

    public required HttpMessage result { get; set; }
    public string? accessToken { get; set; }
    public SessionCredential? session { get; set; }
    public string? twoFactorAccessToken { get; set; }
    public List<TwoFactorAuthMethod>? twoFactorAuthMethods { get; set; }
    public List<TwoFactorAuthConfiguration>? availableTwoFactorAuthConfigurations { get; set; }
    public Duration? lockoutDuration { get; set; }
}
