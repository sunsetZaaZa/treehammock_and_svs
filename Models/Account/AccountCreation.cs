using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;
using NodaTime;

namespace treehammock.Models.Account;

public class AccountCreationRequest : IValidatableObject
{
    public const int MaxUsernameLength = 128;
    public const int MaxEmailAddressLength = 1024;
    public const int MaxPasswordLength = 512;

    public AccountCreationRequest()
    {
    }

    [SetsRequiredMembers]
    public AccountCreationRequest(string emailAddress, string password)
    {
        (this.emailAddress, this.username, this.password, this.country) =
        (emailAddress, null, password, Country.NONE);
    }

    [SetsRequiredMembers]
    public AccountCreationRequest(string emailAddress, string username, string password, Country country)
    {
        (this.emailAddress, this.username, this.password, this.country) =
        (emailAddress, username, password, country);
    }

    [Required(AllowEmptyStrings = false)]
    [EmailAddress]
    [StringLength(MaxEmailAddressLength)]
    public string emailAddress { get; set; } = string.Empty;

    [StringLength(MaxUsernameLength)]
    public string? username { get; set; }

    [Required(AllowEmptyStrings = false)]
    [StringLength(MaxPasswordLength)]
    public string password { get; set; } = string.Empty;

    [EnumDataType(typeof(Country))]
    public Country country { get; set; } = Country.NONE;

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (country == Country.NONE)
        {
            yield return new ValidationResult(
                "A supported country is required.",
                new[] { nameof(country) });
        }
    }

}

public class AccountCreationResponse
{
    [SetsRequiredMembers]
    public AccountCreationResponse(HttpMessage status, Instant? createdOn)
    {
        (this.status, this.createdOn) = (status, createdOn);
    }

    public required HttpMessage status { get; set; }
    public Instant? createdOn { get; set; }
}


public class AccountVerificationResendRequest
{
    [SetsRequiredMembers]
    public AccountVerificationResendRequest(string emailAddress)
    {
        this.emailAddress = emailAddress;
    }

    [Required(AllowEmptyStrings = false)]
    [EmailAddress]
    [StringLength(AccountCreationRequest.MaxEmailAddressLength)]
    public string emailAddress { get; set; } = string.Empty;
}

public class AccountVerificationResendResponse
{
    [SetsRequiredMembers]
    public AccountVerificationResendResponse(HttpMessage status)
    {
        this.status = status;
    }

    public required HttpMessage status { get; set; }
}
