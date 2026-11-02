using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;

using treehammock.RiggingSupport.Status;

namespace treehammock.Models.Activation;

public class ActivationDetailsRequest
{
    public int version { get; set; } = 2;
    public Guid grantId { get; set; }
    public long grantVersion { get; set; }
    public Guid requestId { get; set; }

    public const int MaxEmailAddressLength = 1024;
    public const int MaxCodeLength = 128;

    [SetsRequiredMembers]
    public ActivationDetailsRequest(string emailAddress, string code) =>
        (this.emailAddress, this.code) = (emailAddress, code);

    [Required(AllowEmptyStrings = false)]
    [EmailAddress]
    [StringLength(MaxEmailAddressLength)]
    public required string emailAddress { get; set; }

    [Required(AllowEmptyStrings = false)]
    [StringLength(MaxCodeLength)]
    public required string code { get; set; }
}

public class ActivationDetailsResponse
{
    public int version { get; set; } = 2;
    public Guid grantId { get; set; }
    public long grantVersion { get; set; }
    public string lifecycle { get; set; } = "denied";
    public bool rightsEnabled { get; set; } = false;
    public NodaTime.Instant? startsAt { get; set; }
    public NodaTime.Instant? eligibilityUntil { get; set; }
    public treehammock.DataLayer.Entitlements.EntitlementProjection? entitlements { get; set; }

    [SetsRequiredMembers]
    public ActivationDetailsResponse(Pass result, string off, uint term, uint featureSet) =>
        (this.result, this.off, this.term, this.featureSet) = (result, off, term, featureSet);

    public required Pass result { get; set; }
    public required string off { get; set; }
    public required uint term { get; set; }
    public required uint featureSet { get; set; }
}
