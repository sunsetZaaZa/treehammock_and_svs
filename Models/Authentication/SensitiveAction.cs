using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;

using NodaTime;

using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;

namespace treehammock.Models.Authentication;

public sealed class ReauthenticateRequest
{
    public const int MaxPasswordLength = 512;

        [SetsRequiredMembers]
    public ReauthenticateRequest()
    {
        password = string.Empty;
        purpose = SensitiveActionPurpose.TWO_FACTOR_AUTHENTICATOR_SETUP;
    }

[SetsRequiredMembers]
    public ReauthenticateRequest(string password)
    {
        this.password = password;
    }

    [Required(AllowEmptyStrings = false)]
    [StringLength(MaxPasswordLength)]
    public string password { get; set; } = string.Empty;

    [StringLength(1024)] public string? target { get; set; }

    public SensitiveActionPurpose purpose { get; set; } = SensitiveActionPurpose.TWO_FACTOR_AUTHENTICATOR_SETUP;
}

public sealed class ReauthenticateResponse
{
    [SetsRequiredMembers]
    public ReauthenticateResponse(
        HttpMessage result,
        string? sensitiveActionToken = null,
        SensitiveActionPurpose? purpose = null,
        Instant? expiration = null, string? proofSession = null)
    {
        this.result = result;
        this.sensitiveActionToken = sensitiveActionToken;
        this.purpose = purpose;
        this.expiration = expiration;
        this.proofSession = proofSession;
    }

    public required HttpMessage result { get; set; }
    public string? sensitiveActionToken { get; set; }
    public SensitiveActionPurpose? purpose { get; set; }
    public Instant? expiration { get; set; }
    public string? proofSession { get; set; }
}

public sealed class SensitiveFactorProofRequest
{
    [Required, StringLength(512, MinimumLength = 16)] public string proofSession { get; set; } = "";
    [Required, RegularExpression("^[0-9]{6,8}$")] public string code { get; set; } = "";
}
