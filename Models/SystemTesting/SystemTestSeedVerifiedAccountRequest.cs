using System.ComponentModel.DataAnnotations;

using treehammock.RiggingSupport.Enum;

namespace treehammock.Models.SystemTesting;

public sealed class SystemTestSeedVerifiedAccountRequest
{
    [Required]
    [EmailAddress]
    public string emailAddress { get; set; } = string.Empty;

    public string? username { get; set; }

    [Required]
    public string password { get; set; } = string.Empty;

    public Country country { get; set; } = Country.USA;
}

public sealed record SystemTestSeedVerifiedAccountResponse(Guid AccountId, Guid AccountSecurityStamp, string EmailAddress, string? Username);
