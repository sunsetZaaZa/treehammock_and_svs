using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;

using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;

namespace treehammock.Models.Activation;

public class ActivationCreationRequest
{
    public int version { get; set; } = 2;
    public Guid grantId { get; set; }
    public long grantVersion { get; set; }

    public const int MaxEmailAddressLength = 1024;

    [SetsRequiredMembers]
    public ActivationCreationRequest(string emailAddress, uint featureSet, DayDuration term, DurationRepeat recycle) =>
        (this.emailAddress, this.featureSet, this.term, this.recycle) = (emailAddress, featureSet, term, recycle);

    [Required(AllowEmptyStrings = false)]
    [EmailAddress]
    [StringLength(MaxEmailAddressLength)]
    public required string emailAddress { get; set; }
    public required uint featureSet { get; set; }
    public required DayDuration term { get; set; }
    public required DurationRepeat recycle { get; set; }
}

public class ActivationCreationResponse
{
    public int version { get; set; } = 2;
    public Guid grantId { get; set; }
    public long grantVersion { get; set; }
    public string lifecycle { get; set; } = "denied";
    public bool rightsEnabled { get; set; } = false;
    public Guid? requestId { get; set; }
    public int? retryAfterSeconds { get; set; }

    [SetsRequiredMembers]
    public ActivationCreationResponse(Pass result) =>
        this.result = result;

    public required Pass result { get; set; }
}
