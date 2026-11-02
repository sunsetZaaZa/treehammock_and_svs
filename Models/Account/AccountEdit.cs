using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;
using treehammock.RiggingSupport.Status;

namespace treehammock.Models.Account;

public class AccountEditRequest
{
    public const int MaxEmailAddressLength = 1024;
    public const int MaxUsernameLength = 128;

    public AccountEditRequest(string? emailAddress, string? username)
    {
        (this.emailAddress, this.username) = (emailAddress, username);
    }

    [EmailAddress]
    [StringLength(MaxEmailAddressLength)]
    public string? emailAddress { get; set; }

    [StringLength(MaxUsernameLength)]
    public string? username { get; set; }
}

public class AccountEditResponse
{
    [SetsRequiredMembers]
    public AccountEditResponse(HttpMessage result)
    {
        (this.result) = (result);
    }

    public required HttpMessage result { get; set; }
}

public class AccountEmailChangeVerifyRequest
{
    public const int MaxEmailChangeTokenLength = 512;

    [SetsRequiredMembers]
    public AccountEmailChangeVerifyRequest() { verifyToken=string.Empty; }

    [SetsRequiredMembers]
    public AccountEmailChangeVerifyRequest(string verifyToken)
    {
        this.verifyToken = verifyToken;
    }

    [Required(AllowEmptyStrings = false)]
    [StringLength(MaxEmailChangeTokenLength)]
    public required string verifyToken { get; set; }
    [StringLength(128)] public string? operationKey { get; set; }
    [StringLength(128)] public string? operationRecovery { get; set; }
}
